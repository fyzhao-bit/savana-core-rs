//! Offline protocol demonstration, not a deployed advisor or business executor.
//! Run: cargo run -p savana-continuation-core --example fused_planning --offline
use savana_continuation_core::planning::*;

fn fake_worker(view: &ModelView) -> Vec<u8> {
    match view.role {
        Role::Advisor => serde_json::to_vec(&ReviewAdvice {
            schema: 1,
            job: view.job,
            view: view.commitment(),
            templates: vec![2],
            questions: vec![],
        })
        .unwrap(),
        Role::Planner => serde_json::to_vec(&PlanProposal {
            schema: 1,
            job: view.job,
            view: view.commitment(),
            choice: PlanChoice::RegisteredTemplate {
                template: view.suggested_templates.first().copied().unwrap_or(1),
            },
        })
        .unwrap(),
    }
}

fn main() {
    let policy = Policy {
        schema: 1,
        root: [1; 32],
        observer_scope: [2; 32],
        operations: (1..=3)
            .map(|id| Operation {
                id,
                tool_class: id,
                action_template: id,
                bindings: vec![SlotBinding {
                    result_of: None,
                    result_path: None,
                    result_max_bytes: None,
                    result_source_clause: None,
                    result_list: false,
                    result_compute: None,
                    argument: "input".into(),
                    slot: [id as u8; 16],
                }],
                after: if id == 1 { vec![] } else { vec![1] },
            })
            .collect(),
        templates: vec![
            Template {
                id: 1,
                order: vec![1, 2, 3],
            },
            Template {
                id: 2,
                order: vec![1, 3, 2],
            },
        ],
        rounds: vec![Round {
            observations: vec![],
            id: 1,
            opens_at: 100,
            advice_cut: 110,
            closes_at: 150,
            advisor: Some([3; 32]),
            planner: [4; 32],
            model_profile: 1,
            mode: Mode::RegisteredTemplateV04,
            public_view:
                b"Select an approved invoice-processing template; all real records stay local."
                    .to_vec(),
            template_ids: vec![1, 2],
            question_codes: vec![],
            max_deliveries: 2,
        }],
        max_replacements: 0,
    };
    // Deterministic IDs are TEST FIXTURES ONLY. The durable host samples them.
    let mut state = PlanningState::new(policy, vec![(Some([5; 16]), [6; 16])]).unwrap();
    let review = state
        .reserve_delivery(1, Role::Advisor, [3; 32], 100)
        .unwrap();
    println!(
        "Frozen ReviewView: {}",
        String::from_utf8(review.canonical_bytes().unwrap()).unwrap()
    );
    let advice = fake_worker(&review);
    state.accept_advice(1, [3; 32], &advice, 101).unwrap();
    assert!(!state.accept_advice(1, [3; 32], &advice, 102).unwrap());
    state.freeze_envelope(1, 110).unwrap();
    let envelope = state
        .reserve_delivery(1, Role::Planner, [4; 32], 110)
        .unwrap();
    println!(
        "Rebuilt PlannerEnvelope: {}",
        String::from_utf8(envelope.canonical_bytes().unwrap()).unwrap()
    );
    state
        .accept_plan(1, [4; 32], &fake_worker(&envelope), 111)
        .unwrap();
    let compiled = state.compiled(1).unwrap();
    println!(
        "Local candidate operation order: {:?}",
        compiled
            .operations()
            .iter()
            .map(|o| o.id)
            .collect::<Vec<_>>()
    );
    println!("No network request, business effect, approval or execution ticket was issued.");
}
