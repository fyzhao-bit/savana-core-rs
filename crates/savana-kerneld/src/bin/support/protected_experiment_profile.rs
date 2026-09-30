//! Fresh-stage synthetic calendar experiment assets. Never a runtime authority
//! endpoint and never re-sign an installed manifest or task root.
use super::*;
use savana_kernel_protocol::v2::{business_target_identity_v2,
    final_result_release_business_profile_v04, ActionCodecProfileV2, BusinessFieldRoleV2 as R,
    BusinessFieldTypeV2 as T, BusinessFieldV2, BusinessMagnitudeV2, BusinessProfileV2, TaskEffectV2};
use savana_policy_core::v2::{BoundedConnectorNameV2, BoundedConnectorUrlV2, ConnectorDescriptorV2,
    ConnectorStructuralRoleV2, ConnectorTransportV2};

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
    let calendar=shipped_connector(&exec["provider"],"dojo-calendar")?;
    let release_connector=shipped_connector(&exec["final_release_provider"],"savana-final-release")?;
    let (mut calendar_tools,mut release_tools)=(Vec::new(),Vec::new());
    for (index,name,parameters,release) in [
        (0,"dojo.calendar.search",vec!["date","query"],false),
        (1,"dojo.calendar.day",vec!["day"],false),
        (2,"savana.final_result_release",vec![],true)] {
        let transport=&exec[if release {"final_release_provider"} else {"provider"}];
        let url=transport["canonical_url"].as_str().ok_or("provider URL missing")?;
        let target=business_target_identity_v2(url,Digest32V2::new(parse_digest(transport,"server_spki_sha256")?))
            .map_err(|_|"target binding")?;
        let credential=Digest32V2::new(parse_digest(transport,"credential_handle_identity_digest")?);
        let profile=if release { final_result_release_business_profile_v04(target,credential).map_err(|_|"release profile")? }
        else {
            let mut fields=vec![("body",R::Payload),("calendar",R::Resource),("to",R::Destination)];
            fields.extend(parameters.iter().map(|p|(*p,R::Parameter)));fields.sort_by_key(|f|f.0);
            BusinessProfileV2::new(ActionCodecProfileV2::McpToolsCallJsonV1,name,target,credential,
                TaskEffectV2::Read,BusinessMagnitudeV2::FixedCount(1),
                fields.into_iter().map(|(n,r)|BusinessFieldV2::new(n,r,T::Text)).collect::<Result<Vec<_>,_>>()
                    .map_err(|_|"business fields")?).map_err(|_|"business profile")?
        };
        let contract=ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt;
        let provider=if release {release_connector.2} else {calendar.2};
        let d=UnsignedToolDescriptorV2::from_verified_manifest(2,VersionV2::new(2,0,0),provider,
            IdentifierV2::new(name).map_err(|_|"tool name")?,ActionTemplateIdV2::new(102+index),ToolClassIdV2::new(202+index),
            profile.digest(),Digest32V2::new(Sha256::digest(if release {b"SAVANA_FIXED_POST_CORRELATED_STATUS_V1\0".as_slice()}
                else {b"SAVANA_MCP_JSON_RESULT_V1\0".as_slice()}).into()),vec![RoleIdV2::new(1)],
            if release {EffectSetV2::FINAL_RELEASE} else {EffectSetV2::READ},
            if release {AttemptKindV2::ToolWrite} else {AttemptKindV2::ToolRead},
            BoundedConnectorRetryPolicyV2::new(contract,1,0).map_err(|_|"retry policy")?,vec![],ExecutorIdentityV2::new(executor),
            ProjectionIdV2::new(1),projection(b"SAVANA_KERNEL_DESTINATION_PROJECTION_V2\0",1),
            DisplayProjectionIdV2::new(1),projection(b"SAVANA_KERNEL_DISPLAY_PROJECTION_V2\0",1),contract,
            UnixMillisV2::new(ACTIVE_NOT_BEFORE),UnixMillisV2::new(ACTIVE_EXPIRES_AT))
            .and_then(|d|d.with_business_profile(profile)).map_err(|_|"descriptor")?;
        let digest=descriptor_digest_v2(&d).map_err(|_|"descriptor digest")?;
        if release {release_tools.push(d.clone())} else {calendar_tools.push(d.clone())}
        let leaf=format!("protected-tool-{index}-v04.cbor");
        write_new(&stage.join("etc/savana/policy").join(&leaf),&sign_descriptor(&d,&registry)?,0o444)?;
        paths.push(format!("/etc/savana/policy/{leaf}"));
        activations.push(json!({"descriptor_digest":hex(*digest.as_bytes()),"registry_ordinal":index,
            "policy_activation_digest":hex(domain_digest(b"SAVANA_PROTECTED_ACTIVATION_V04\0",digest.as_bytes()))}));
        constraints.push(json!({"descriptor_digest":hex(*digest.as_bytes()),"maximum_attempts":1,"maximum_elapsed_ns":0,"internal_validators":[]}));
        descriptors.insert(name.into(),json!(hex(*digest.as_bytes())));
        catalog.push(json!({"tool_class":202+index,"action_template":102+index,
            "structural_role":savana_policy_core::v2::ConnectorStructuralRoleV2::Sink.tag(),
            "effects":if release {EffectSetV2::FINAL_RELEASE.bits()}else{EffectSetV2::READ.bits()},
            "semantic_name":name,"semantic_description":"Reviewed finite experiment operation"}));
        // Use the exact native transport URL, not a similar-looking guessed path.
        endpoints[if release {"release_provider"}else{"provider"}]["url"]=json!(url);
    }
    activations.sort_by_key(|v|v["descriptor_digest"].as_str().unwrap().to_owned());
    // G7 routes an authorized task tool only through a registered connector.
    // Ship both in the measured daemon configs, bound to the genesis head.
    let mut connectors=[(calendar,calendar_tools,EffectSetV2::READ),
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
    let destination=final_release_destination_digest(executor);
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
        "destination_digest":hex(destination),"store":kernel["g4_store_id"],
        "installation":manifest["installation_id"],"disposition":"require_approval",
        "scope":"finite_calendar_subset","task_grants_installed":false});
    write_json(&stage.join("etc/savana/experiment-provisioning-v04.json"),&binding)?;
    write_json(&stage.join("protected-experiment-profile.json"),&json!({"schema":1,"tools":3,"g3_rules":6,
        "deployment_shipped_connectors":connectors.len(),"installed":false}))?;
    Ok(())
}
