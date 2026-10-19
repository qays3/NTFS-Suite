async function call(method, path, body) {
  const options = {
    method,
    headers: {
      "content-type": "application/json",
    },
  };
  if (body !== undefined) {
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.status.toString());
  }
  return response.json();
}

export const api = {
  bootstrap: () => call("GET", "/api/bootstrap"),
  setup: (data) => call("POST", "/api/setup", data),
  listCases: () => call("GET", "/api/cases"),
  createCase: (data) => call("POST", "/api/cases", data),
  openCase: (file) => call("POST", "/api/cases/open", { file }),
  deleteCase: (file) => call("POST", "/api/cases/delete", { file }),
  caseState: () => call("GET", "/api/case"),
  auditLog: () => call("GET", "/api/case/audit"),
  setTimezone: (timezone) => call("POST", "/api/case/timezone", { timezone }),
  browse: (path) => call("POST", "/api/browse", { path }),
  pick: (kind) => call("POST", "/api/pick", { kind }),
  evidenceStats: (evidence_id) => call("POST", "/api/evidence/stats", { evidence_id }),
  jobStatus: (job_id) => call("POST", "/api/jobs/status", { job_id }),
  jobCancel: (job_id) => call("POST", "/api/jobs/cancel", { job_id }),
  addEvidence: (path) => call("POST", "/api/evidence", { path }),
  deleteEvidence: (evidence_id) => call("POST", "/api/evidence/delete", { evidence_id }),
  parseEvidence: (data) => call("POST", "/api/evidence/parse", data),
  records: (data) => call("POST", "/api/records", data),
  findings: (data) => call("POST", "/api/findings", data),
  findingsGrouped: (data) => call("POST", "/api/findings/grouped", data),
  findingStatus: (data) => call("POST", "/api/findings/status", data),
  findingStatusGroup: (data) => call("POST", "/api/findings/status/group", data),
  detect: (evidence_id) => call("POST", "/api/detect", { evidence_id }),
  rulesList: () => call("GET", "/api/rules"),
  rulesPreview: (evidence_id, rule) => call("POST", "/api/rules/preview", { evidence_id, rule }),
  rulesSave: (rule) => call("POST", "/api/rules/save", rule),
  rulesDelete: (id) => call("POST", "/api/rules/delete", { id }),
  rulesEnable: (rule_id, enabled) => call("POST", "/api/rules/enable", { rule_id, enabled }),
  iocList: () => call("GET", "/api/iocs"),
  iocImport: (text, format) => call("POST", "/api/iocs/import", { text, format }),
  iocClear: () => call("POST", "/api/iocs/clear"),
  chartsDashboard: (data) => call("POST", "/api/charts/dashboard", data),
  graphRoots: (evidence_id) => call("POST", "/api/graph/roots", { evidence_id }),
  graphNeighbors: (evidence_id, id) => call("POST", "/api/graph/neighbors", { evidence_id, id }),
  graphAnatomy: (evidence_id) => call("POST", "/api/graph/anatomy", { evidence_id }),
  graphOwnership: (evidence_id) => call("POST", "/api/graph/ownership", { evidence_id }),
  usnList: (data) => call("POST", "/api/usn", data),
  collectVolumes: () => call("GET", "/api/collect/volumes"),
  collectRun: (data) => call("POST", "/api/collect/run", data),
  secureLookup: (data) => call("POST", "/api/secure/lookup", data),
  timelineEvents: (evidence_id, entries) => call("POST", "/api/timeline/events", { evidence_id, entries }),
  timelineBodyfile: (path, search) => call("POST", "/api/timeline/bodyfile", { path, search }),
  timelineBodyfileDefault: (evidence_id, search) => call("POST", "/api/timeline/bodyfile/default", { evidence_id, search }),
};
