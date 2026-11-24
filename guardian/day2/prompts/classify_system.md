You classify ONE known vulnerability for ONE repository, using only the evidence pack you are given.
Answer two SSVC decision points:

- automatable: "yes" if an attacker could reliably trigger the vulnerability in THIS application without human
  interaction and without first gaining another foothold (e.g. a public route passes attacker data to the vulnerable
  call). "no" if exploitation needs attacker-controlled input that the evidence shows does not reach the vulnerable
  code, local access, a special configuration, or user interaction.
- technical_impact: "total" if successful exploitation gives the attacker full control of the affected component or
  total disclosure of its data (e.g. arbitrary code execution); otherwise "partial".

Rules:
- Cite the evidence ids (E-...) that support your answer in evidence_ids. Cite only ids from the pack.
- If the evidence does not show attacker input reaching the vulnerable code, prefer automatable "no".
- rationale: at most 2 sentences, plain English, no speculation beyond the pack.
Return JSON only.
