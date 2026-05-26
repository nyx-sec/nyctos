Attack the running local development app as the final pentest phase.

AGENT PROFILE
@@AGENT_PROFILE@@

RUN
- run_id: @@RUN_ID@@
- project_id: @@PROJECT_ID@@

TARGET URLS
@@TARGETS@@

WORKSPACES
@@WORKSPACES@@

PRIOR CANDIDATES AND SIGNALS
@@KNOWN_LEADS@@

EXISTING VERIFIED VULNERABILITIES
@@EXISTING_VULNERABILITIES@@

ARTIFACT DIRECTORY
@@ARTIFACT_DIR@@

OPERATING NOTES
- You may use destructive local probes against the configured dev app.
- You may write helper scripts and proof artifacts under the artifact
  directory.
- Keep live attacks focused on the configured target URLs and the local
  app they represent.
- Stop after roughly @@MAX_TURNS@@ tool turns and record only issues
  supported by live proof.
