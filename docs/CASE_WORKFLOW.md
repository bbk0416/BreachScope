# Case Workflow

BreachScope keeps generated evidence (findings, artifacts, manifests, hashes) separate from analyst-owned workflow fields. This lets an analyst triage and annotate a case without changing the original analysis output.

## Workflow fields

Each case can store:

- `workflow_status`: `new`, `triage`, `investigating`, `contained`, `resolved`, `false_positive`
- `assignee`: analyst or team responsible for follow-up
- `tags`: normalized labels such as `powershell`, `priority-high`, `customer-a`
- `severity_override`: optional analyst override of the generated risk level
- `notes`: investigation notes
- `closure_summary`: final disposition or false-positive rationale
- `updated_by` / `updated_at`: who changed the workflow and when

The generated report artifacts remain immutable from the workflow endpoint.

## API

```http
GET /api/cases/workflow/summary
PATCH /api/cases/{case_id}/workflow
```

Example update:

```bash
curl -X PATCH http://localhost:8000/api/cases/case-id/workflow \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $BS_API_KEY" \
  -d '{
    "workflow_status": "investigating",
    "assignee": "analyst-a",
    "tags": ["powershell", "priority-high"],
    "notes": "Parent process and user context are being reviewed.",
    "severity_override": "critical"
  }'
```

Workflow updates are written to the audit log as `case.workflow.update`.
