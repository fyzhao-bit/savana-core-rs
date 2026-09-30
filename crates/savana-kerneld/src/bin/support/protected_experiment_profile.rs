//! Fresh-stage synthetic calendar experiment assets. Never a runtime authority
//! endpoint and never re-sign an installed manifest or task root.
use super::*;
use savana_kernel_protocol::v2::{business_target_identity_v2,
    final_result_release_business_profile_v04, final_result_release_business_request_v04, ActionCodecProfileV2, BusinessFieldRoleV2 as R,
    BusinessFieldTypeV2 as T, BusinessFieldV2, BusinessMagnitudeV2, BusinessProfileV2, ImplementationIdV2, TaskEffectV2};
use savana_policy_core::v2::{deployment_requires_intent_flow_confinement, BoundedConnectorNameV2,
    BoundedConnectorUrlV2, ConnectorDescriptorV2, ConnectorStructuralRoleV2, ConnectorTransportV2,
    InternalValidatorDeclarationV2};

fn parse_digest(v: &Value, key: &str) -> Result<[u8;32], String> {
    let s=v[key].as_str().ok_or("missing digest")?;
    if s.len()!=64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("invalid digest".into());
    }
    let mut out=[0;32];
    for (i,b) in out.iter_mut().enumerate() { *b=u8::from_str_radix(&s[i*2..i*2+2],16).map_err(|_|"digest")?; }
    if out==[0;32] { return Err("zero digest".into()); }
    Ok(out)
}
fn read(root:&Path, name:&str)->Result<Value,String> {
    let p=root.join(name);
    let m=fs::symlink_metadata(&p).map_err(|_|"stage file missing")?;
    if !m.is_file() || m.file_type().is_symlink() || m.len()>262144 {return Err("invalid stage file".into());}
    serde_json::from_slice(&fs::read(p).map_err(|_|"stage read")?).map_err(|_|"stage JSON".into())
}
fn replace(root:&Path,name:&str,bytes:&[u8])->Result<(),String> {
    let path=root.join(name);
    let meta=fs::symlink_metadata(&path).map_err(|_|"missing stage output")?;
    if !meta.is_file() || meta.file_type().is_symlink() {return Err("invalid stage output".into());}
    let temporary=path.with_extension("protected-new");
    write_new(&temporary, bytes, 0o444)?;
    fs::rename(temporary,path).map_err(|_|"stage publication failed".into())
}
fn replace_json(root:&Path,name:&str,v:&Value)->Result<(),String> {
    replace(root,name,&serde_json::to_vec(v).map_err(|_|"JSON encoding")?)
}
fn hex_bytes(bytes:&[u8])->String {
    bytes.iter().map(|b|format!("{b:02x}")).collect()
}
fn field_role(s:&str)->Result<R,String> {
    match s {"payload"=>Ok(R::Payload),"resource"=>Ok(R::Resource),
        "destination"=>Ok(R::Destination),"parameter"=>Ok(R::Parameter),_=>Err("field role".into())}
}
fn field_type(s:&str)->Result<T,String> {
    match s {"text"=>Ok(T::Text),_=>Err("field type".into())}
}
/// The intent-flow-confinement validator's fixed build identity (id 6, v1.0.0).
/// A declaration and its registry build must carry the same non-zero digest;
/// this is a manifest identity, not a hash of validator code.
const CONFINEMENT_IMPLEMENTATION_ID:u32=6;
fn confinement_build_digest()->Digest32V2 {
    Digest32V2::new(domain_digest(b"SAVANA_PROTECTED_VALIDATOR_BUILD_V04\0",
        &[CONFINEMENT_IMPLEMENTATION_ID as u8]))
}
fn confinement_declaration()->InternalValidatorDeclarationV2 {
    InternalValidatorDeclarationV2::new(ImplementationIdV2::new(CONFINEMENT_IMPLEMENTATION_ID),
        VersionV2::new(1,0,0),confinement_build_digest())
}
/// Map a reviewed catalog effect string to the closed protocol effect/effect
/// set and attempt kind. Reads are steerable; every authorizing effect is a
/// tool write.
fn tool_effect(effect:&str)->Result<(TaskEffectV2,EffectSetV2,AttemptKindV2),String> {
    Ok(match effect {
        "read"=>(TaskEffectV2::Read,EffectSetV2::READ,AttemptKindV2::ToolRead),
        "create"=>(TaskEffectV2::Create,EffectSetV2::CREATE,AttemptKindV2::ToolWrite),
        "update"=>(TaskEffectV2::Update,EffectSetV2::UPDATE,AttemptKindV2::ToolWrite),
        "delete"=>(TaskEffectV2::Delete,EffectSetV2::DELETE,AttemptKindV2::ToolWrite),
        "send"=>(TaskEffectV2::Send,EffectSetV2::SEND,AttemptKindV2::ToolWrite),
        "execute"=>(TaskEffectV2::Execute,EffectSetV2::EXECUTE,AttemptKindV2::ToolWrite),
        _=>return Err("catalog effect".into()),
    })
}
/// One reviewed workspace tool the deployment ships: its operation, business
/// fields, effect, and required internal validators.
struct CatalogToolV04 {
    operation: String,
    fields: Vec<(String,R,T)>,
    effect: TaskEffectV2,
    effect_set: EffectSetV2,
    attempt: AttemptKindV2,
    validators: Vec<InternalValidatorDeclarationV2>,
}
fn parse_catalog_fields(tool:&Value)->Result<Vec<(String,R,T)>,String> {
    let raw=tool["fields"].as_array().ok_or("catalog fields")?;
    let mut fields=Vec::new();
    for field in raw {
        fields.push((field["name"].as_str().ok_or("field name")?.to_owned(),
            field_role(field["role"].as_str().ok_or("field role")?)?,
            field_type(field["type"].as_str().ok_or("field type")?)?));
    }
    Ok(fields)
}
/// Parse the reviewed tool catalog the staging step copied in. Only operation
/// names, business field roles/types, effects and required validators are read;
/// it authorizes no target, credential or value and never re-signs a manifest.
/// Every authorizing (write) tool must declare intent-flow-confinement.
fn tool_catalog(stage:&Path)->Result<Vec<CatalogToolV04>,String> {
    let doc=read(stage,"etc/savana/read-tool-catalog-v04.json")?;
    if doc["schema"]!=json!(2) {return Err("tool catalog schema".into());}
    let reads=doc["read_tools"].as_array().ok_or("catalog read tools")?;
    let writes=doc["write_tools"].as_array().ok_or("catalog write tools")?;
    if reads.is_empty() || reads.len()+writes.len()>64 {return Err("catalog size".into());}
    let mut out=Vec::new();
    for tool in reads {
        if tool["effect"]!=json!("read") || tool["fixed_magnitude"]!=json!(1) {
            return Err("catalog read operation".into());
        }
        let (effect,effect_set,attempt)=tool_effect("read")?;
        out.push(CatalogToolV04{
            operation:tool["operation"].as_str().ok_or("catalog operation name")?.to_owned(),
            fields:parse_catalog_fields(tool)?,effect,effect_set,attempt,validators:Vec::new()});
    }
    for tool in writes {
        if tool["fixed_magnitude"]!=json!(1) {return Err("catalog write magnitude".into());}
        let (effect,effect_set,attempt)=tool_effect(tool["effect"].as_str().ok_or("catalog write effect")?)?;
        // A write tool declares exactly the intent-flow-confinement validator.
        let names=tool["validators"].as_array().ok_or("catalog validators")?;
        if names.iter().map(|v|v.as_str()).collect::<Option<Vec<_>>>()
            !=Some(vec!["intent_flow_confinement"]) {
            return Err("catalog write validators".into());
        }
        let validators=vec![confinement_declaration()];
        // The deployment rule: a state-changing tool must bind confinement.
        if !deployment_requires_intent_flow_confinement(effect_set,&validators) {
            return Err("authorizing tool without confinement".into());
        }
        out.push(CatalogToolV04{
            operation:tool["operation"].as_str().ok_or("catalog operation name")?.to_owned(),
            fields:parse_catalog_fields(tool)?,effect,effect_set,attempt,validators});
    }
    Ok(out)
}
/// One deployment-shipped connector per native provider transport. Its id,
/// not the business target, is each tool descriptor's provider identity.
fn shipped_connector(transport:&Value,name:&str)
    ->Result<(BoundedConnectorNameV2,ConnectorTransportV2,Digest32V2),String> {
    let url=transport["canonical_url"].as_str().ok_or("provider URL missing")?;
    let name=BoundedConnectorNameV2::new(name).map_err(|_|"connector name")?;
    let transport=ConnectorTransportV2::https(BoundedConnectorUrlV2::new(url).map_err(|_|"connector URL")?,
        Digest32V2::new(parse_digest(transport,"server_spki_sha256")?)).map_err(|_|"connector transport")?;
    let id=ConnectorDescriptorV2::deployment_shipped_id(&name,&transport).map_err(|_|"connector id")?;
    Ok((name,transport,id))
}
fn projection(domain:&[u8],id:u32)->Digest32V2 {
    let mut h=Sha256::new();h.update(domain);h.update(4u64.to_be_bytes());h.update(id.to_be_bytes());
    Digest32V2::new(h.finalize().into())
}
fn sign_descriptor(d:&UnsignedToolDescriptorV2,key:&SigningKey)->Result<Vec<u8>,String> {
    let payload=minicbor::to_vec(d).map_err(|_|"descriptor encoding")?;
    let digest=descriptor_digest_v2(d).map_err(|_|"descriptor digest")?;
    let mut signed=Vec::from(TOOL_DESCRIPTOR_SIGNATURE_DOMAIN);signed.extend_from_slice(digest.as_bytes());
    let mut e=minicbor::Encoder::new(Vec::new());
    e.array(3).and_then(|e|e.bytes(&payload))
        .and_then(|e|e.bytes(derive_ed25519_key_id_v2(key.verifying_key().to_bytes()).as_bytes()))
        .and_then(|e|e.bytes(&key.sign(&signed).to_bytes())).map_err(|_|"descriptor sign")?;
    Ok(e.into_writer())
}

pub(super) fn materialize(stage:&Path)->Result<(),String> {
    if !cfg!(debug_assertions) || !stage.is_absolute() || stage==Path::new("/")
        || stage.join("etc/savana/deployment-manifest-v2.cbor").exists()
        || stage.join("var/lib/savana").exists()
        || stage.join("protected-experiment-profile.json").exists() {
        return Err("fresh unsigned disposable stage required".into());
    }
    let meta=fs::symlink_metadata(stage).map_err(|_|"stage missing")?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode()&0o077!=0 {
        return Err("private stage required".into());
    }
    let report=read(stage,"integration-report.json")?;
    if report["installed"]!=false || report["protected_experiment_transport_configured"]!=true {
        return Err("opt-in experimental stage required".into());
    }
    let mut kernel=read(stage,"etc/savana/kerneld-bootstrap-v2.json")?;
    let mut exec=read(stage,"etc/savana/execd-bootstrap-v2.json")?;
    let mut agent=read(stage,"etc/savana/agentd-bootstrap-v2.json")?;
    let mut manifest=read(stage,"etc/savana/integration-manifest-input.json")?;
    let mut endpoints=read(stage,"etc/savana/experiment-endpoints-v04.json")?;
    let identity=read(stage,"etc/savana/experiment-model-identity.json")?;
    let recipient=parse_digest(&identity,"recipient")?;
    if exec["provider_routing_mode"]!="split-final-release" {return Err("split provider required".into());}
    let mut issued=HashSet::new();
    let registry=signing_key(&mut issued)?;
    let executor=parse_digest(&kernel["policy_runtime"],"executor_identity")?;
    let mut paths=Vec::new();let mut activations=Vec::new();let mut constraints=Vec::new();
    let mut descriptors=serde_json::Map::new();let mut catalog=Vec::new();
    // One shipped connector carries every reviewed read tool (the single native
    // workspace provider endpoint); a separate connector carries final release.
    let workspace=shipped_connector(&exec["provider"],"dojo-workspace")?;
    let release_connector=shipped_connector(&exec["final_release_provider"],"savana-final-release")?;
    let (mut workspace_tools,mut release_tools)=(Vec::new(),Vec::new());
    // Ordered registry: each reviewed catalog tool (reads then writes), then the
    // one fixed final-result-release tool. Indices drive the tool class/template
    // and the signed descriptor leaf, so this order is the deployment tool order.
    let catalog_tools=tool_catalog(stage)?;
    let tool_count=catalog_tools.len()+1;
    // The workspace connector carries every read AND write tool on one native
    // provider endpoint; its effect set is the union it must authorize.
    let mut workspace_effects=EffectSetV2::EMPTY;
    let mut needs_confinement_build=false;
    enum Spec { Tool(CatalogToolV04), Release }
    let mut specs:Vec<Spec>=catalog_tools.into_iter().map(Spec::Tool).collect();
    specs.push(Spec::Release);
    for (index,spec) in specs.into_iter().enumerate() {
        let ordinal=u32::try_from(index).map_err(|_|"tool index")?;
        let release=matches!(spec,Spec::Release);
        let (operation,fields,effect,effect_set,attempt,validators)=match spec {
            Spec::Tool(t)=>(t.operation,t.fields,t.effect,t.effect_set,t.attempt,t.validators),
            Spec::Release=>("savana.final_result_release".to_owned(),Vec::new(),
                TaskEffectV2::FinalRelease,EffectSetV2::FINAL_RELEASE,AttemptKindV2::ToolWrite,Vec::new()),
        };
        let transport=&exec[if release {"final_release_provider"} else {"provider"}];
        let url=transport["canonical_url"].as_str().ok_or("provider URL missing")?;
        let target=business_target_identity_v2(url,Digest32V2::new(parse_digest(transport,"server_spki_sha256")?))
            .map_err(|_|"target binding")?;
        let credential=Digest32V2::new(parse_digest(transport,"credential_handle_identity_digest")?);
        let profile=if release { final_result_release_business_profile_v04(target,credential).map_err(|_|"release profile")? }
        else {
            let mut fields=fields;fields.sort_by(|a,b|a.0.cmp(&b.0));
            BusinessProfileV2::new(ActionCodecProfileV2::McpToolsCallJsonV1,operation.as_str(),target,credential,
                effect,BusinessMagnitudeV2::FixedCount(1),
                fields.into_iter().map(|(n,r,t)|BusinessFieldV2::new(n.as_str(),r,t)).collect::<Result<Vec<_>,_>>()
                    .map_err(|_|"business fields")?).map_err(|_|"business profile")?
        };
        let contract=ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt;
        let provider=if release {release_connector.2} else {workspace.2};
        let d=UnsignedToolDescriptorV2::from_verified_manifest(2,VersionV2::new(2,0,0),provider,
            IdentifierV2::new(operation.as_str()).map_err(|_|"tool name")?,ActionTemplateIdV2::new(102+ordinal),ToolClassIdV2::new(202+ordinal),
            profile.digest(),Digest32V2::new(Sha256::digest(if release {b"SAVANA_FIXED_POST_CORRELATED_STATUS_V1\0".as_slice()}
                else {b"SAVANA_MCP_JSON_RESULT_V1\0".as_slice()}).into()),vec![RoleIdV2::new(1)],
            effect_set,attempt,
            BoundedConnectorRetryPolicyV2::new(contract,1,0).map_err(|_|"retry policy")?,validators.clone(),ExecutorIdentityV2::new(executor),
            ProjectionIdV2::new(1),projection(b"SAVANA_KERNEL_DESTINATION_PROJECTION_V2\0",1),
            DisplayProjectionIdV2::new(1),projection(b"SAVANA_KERNEL_DISPLAY_PROJECTION_V2\0",1),contract,
            UnixMillisV2::new(ACTIVE_NOT_BEFORE),UnixMillisV2::new(ACTIVE_EXPIRES_AT))
            .and_then(|d|d.with_business_profile(profile)).map_err(|_|"descriptor")?;
        let digest=descriptor_digest_v2(&d).map_err(|_|"descriptor digest")?;
        if release {release_tools.push(d.clone())} else {workspace_tools.push(d.clone());workspace_effects=workspace_effects.union(effect_set);}
        if !validators.is_empty() {needs_confinement_build=true;}
        // Manifest constraint validators must equal the descriptor's exactly;
        // the only validator a reviewed write tool carries is confinement.
        let constraint_validators:Vec<Value>=validators.iter().map(|_|json!({
            "implementation_id":CONFINEMENT_IMPLEMENTATION_ID,"semantic_version":[1,0,0],
            "build_manifest_digest":hex(*confinement_build_digest().as_bytes())})).collect();
        let leaf=format!("protected-tool-{index}-v04.cbor");
        write_new(&stage.join("etc/savana/policy").join(&leaf),&sign_descriptor(&d,&registry)?,0o444)?;
        paths.push(format!("/etc/savana/policy/{leaf}"));
        activations.push(json!({"descriptor_digest":hex(*digest.as_bytes()),"registry_ordinal":index,
            "policy_activation_digest":hex(domain_digest(b"SAVANA_PROTECTED_ACTIVATION_V04\0",digest.as_bytes()))}));
        constraints.push(json!({"descriptor_digest":hex(*digest.as_bytes()),"maximum_attempts":1,"maximum_elapsed_ns":0,"internal_validators":constraint_validators}));
        descriptors.insert(operation.clone(),json!(hex(*digest.as_bytes())));
        catalog.push(json!({"tool_class":202+ordinal,"action_template":102+ordinal,
            "structural_role":savana_policy_core::v2::ConnectorStructuralRoleV2::Sink.tag(),
            "effects":effect_set.bits(),
            "semantic_name":operation,"semantic_description":"Reviewed finite experiment operation"}));
        // Use the exact native transport URL, not a similar-looking guessed path.
        endpoints[if release {"release_provider"}else{"provider"}]["url"]=json!(url);
    }
    activations.sort_by_key(|v|v["descriptor_digest"].as_str().unwrap().to_owned());
    // G7 routes an authorized task tool only through a registered connector.
    // Ship both in the measured daemon configs, bound to the genesis head.
    let mut connectors=[(workspace,workspace_tools,workspace_effects),
        (release_connector,release_tools,EffectSetV2::FINAL_RELEASE)].into_iter()
        .map(|((name,transport,_),tools,effects)|ConnectorDescriptorV2::new_deployment_shipped(
            name,transport,tools,effects,ConnectorStructuralRoleV2::Sink,1).map_err(|_|"shipped connector".to_owned()))
        .collect::<Result<Vec<_>,String>>()?;
    connectors.sort_by_key(|c|*c.connector_id().as_bytes());
    let genesis=hex(*ConnectorDescriptorV2::deployment_genesis_digest(&connectors)
        .map_err(|_|"connector genesis")?.as_bytes());
    let shipped:Vec<String>=connectors.iter().map(|c|hex_bytes(c.canonical_bytes())).collect();
    let previous=kernel["policy_runtime"]["connector_registry_genesis_digest"].clone();
    if !previous.is_string() || [&kernel["policy_runtime"]["executor_connector_registry_digest"],
        &exec["connector_set_digest"],&exec["connector_registry_genesis_digest"]].iter().any(|v|**v!=previous)
        || exec.get("deployment_shipped_connectors").is_some()
        || kernel["policy_runtime"].get("deployment_shipped_connectors").is_some() {
        return Err("unexpected connector genesis".into());
    }
    for (object,keys) in [(&mut kernel["policy_runtime"],["executor_connector_registry_digest","connector_registry_genesis_digest"]),
        (&mut exec,["connector_set_digest","connector_registry_genesis_digest"])] {
        for key in keys {object[key]=json!(genesis);}
        object["deployment_shipped_connectors"]=json!(shipped);
    }
    constraints.sort_by_key(|v|v["descriptor_digest"].as_str().unwrap().to_owned());
    let policy=&mut kernel["policy_runtime"];
    policy["registry_publisher_key_id"]=json!(hex(*derive_ed25519_key_id_v2(registry.verifying_key().to_bytes()).as_bytes()));
    policy["registry_publisher_public_key"]=json!(hex(registry.verifying_key().to_bytes()));
    policy["signed_tool_descriptor_paths"]=json!(paths);policy["policy_activations"]=json!(activations);policy["manifest_constraints"]=json!(constraints);
    // Register the intent-flow-confinement validator build so every write tool's
    // declaration activates at G5. The template ships no builds; adding a write
    // tool is the only reason this deployment needs one.
    if needs_confinement_build {
        if policy["validator_builds"].as_array().map(|b|!b.is_empty()).unwrap_or(true) {
            return Err("unexpected validator builds".into());
        }
        policy["validator_builds"]=json!([{"kind":CONFINEMENT_IMPLEMENTATION_ID,
            "implementation_id":CONFINEMENT_IMPLEMENTATION_ID,"semantic_version":[1,0,0],
            "build_manifest_digest":hex(*confinement_build_digest().as_bytes())}]);
    }
    agent["planner_shipped_catalog"]=json!(catalog);
    let input_key=signing_key(&mut issued)?;
    let input_id=derive_ed25519_key_id_v2(input_key.verifying_key().to_bytes());
    let assets=signed_input_assets_for_profile(&input_key,input_id,true)?;
    kernel["input_runtime_publisher_key_id"]=json!(hex(*input_id.as_bytes()));
    kernel["input_runtime_publisher_public_key"]=json!(hex(input_key.verifying_key().to_bytes()));
    replace(stage,"etc/savana/input-runtime-assets-v2.cbor",&assets)?;
    let family=Digest32V2::new(random_unique(&mut issued)?);
    let installer=signing_key(&mut issued)?;let authority=signing_key(&mut issued)?;
    let member=OperationalTrustRootSetItemV2::new(OperationalTrustRootPurposeV2::DeclassificationAuthority,
        authority.verifying_key().to_bytes(),1,ACTIVE_NOT_BEFORE,ACTIVE_EXPIRES_AT).map_err(|_|"G3 member")?;
    let roots=OperationalTrustRootSetV2::new_declassification_signed_for_test(family,1,None,vec![member],
        ACTIVE_NOT_BEFORE,ACTIVE_EXPIRES_AT,&installer,1).map_err(|_|"G3 roots")?;
    // The kernel's FinalRelease sink is the task-bound business destination:
    // the release gateway target plus "application-turn:<turn>". Pin one turn
    // (this deployment's single result receiver) and derive its sink with the
    // kernel's own request codec, so the signed G3 reader is that sink exactly.
    let turn=Digest32V2::new(random_unique(&mut issued)?);
    let release=&exec["final_release_provider"];
    let release_profile=final_result_release_business_profile_v04(
        business_target_identity_v2(release["canonical_url"].as_str().ok_or("release URL missing")?,
            Digest32V2::new(parse_digest(release,"server_spki_sha256")?)).map_err(|_|"release target")?,
        Digest32V2::new(parse_digest(release,"credential_handle_identity_digest")?)).map_err(|_|"release profile")?;
    let destination=*final_result_release_business_request_v04(&release_profile,"destination-reader",
        Digest32V2::new([1;32]),turn,b"reader").map_err(|_|"release destination")?.destination_digest().as_bytes();
    let mut rules=development_declassification_rules(Digest32V2::new(executor),Digest32V2::new(destination))?;
    rules.push(DeclassificationRuleV2::new_for_test(6,ClosedDeclassificationPurposeV2::FusedModelCall,
        declassification_implementation_digest_v2(6).ok_or("G3 transition")?,LeakGateDutyV2::BlocklistOnly,
        Some(vec![Digest32V2::new(recipient)]),None,ACTIVE_NOT_BEFORE,ACTIVE_EXPIRES_AT).map_err(|_|"G3 fused rule")?);
    let rules=DeclassificationRuleSetV2::new_signed_for_test(family,1,None,rules,ACTIVE_NOT_BEFORE,
        ACTIVE_EXPIRES_AT,&roots,&authority,1,ACTIVE_NOT_BEFORE).map_err(|_|"G3 rule set")?;
    manifest["declassification_rule_set_digest"]=json!(hex(*rules.signed_digest().as_bytes()));
    replace_json(stage,"etc/savana/trust/declassification-installer-root-v2.json",&json!({
        "key_id":hex(*derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()).as_bytes()),"key_epoch":1,
        "public_key":hex(installer.verifying_key().to_bytes())}))?;
    replace(stage,"etc/savana/trust/declassification-trust-root-set-v2.cbor",roots.canonical_bytes())?;
    replace(stage,"etc/savana/policy/declassification-rule-set-v2.cbor",rules.canonical_bytes())?;
    replace_json(stage,"etc/savana/kerneld-bootstrap-v2.json",&kernel)?;
    replace_json(stage,"etc/savana/execd-bootstrap-v2.json",&exec)?;
    replace_json(stage,"etc/savana/agentd-bootstrap-v2.json",&agent)?;
    replace_json(stage,"etc/savana/integration-manifest-input.json",&manifest)?;
    replace_json(stage,"etc/savana/experiment-endpoints-v04.json",&endpoints)?;
    let binding=json!({"schema":1,"descriptors":descriptors,"planner":hex(recipient),
        "destination_digest":hex(destination),"application_turn":hex(*turn.as_bytes()),
        "store":kernel["g4_store_id"],
        "installation":manifest["installation_id"],"disposition":"require_approval",
        "scope":"finite_workspace_read_subset","task_grants_installed":false});
    write_json(&stage.join("etc/savana/experiment-provisioning-v04.json"),&binding)?;
    write_json(&stage.join("protected-experiment-profile.json"),&json!({"schema":1,"tools":tool_count,"g3_rules":6,
        "deployment_shipped_connectors":connectors.len(),"installed":false}))?;
    Ok(())
}
