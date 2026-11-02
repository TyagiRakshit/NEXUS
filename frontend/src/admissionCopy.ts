const reasons: Record<string, string> = {
  WARMING: "Collecting eligible observations before a baseline is established.",
  NONCOMPARABLE_WINDOW: "This capture window is not comparable with the required learning window; analysis remains available but learning is blocked.",
  WARMUP_STARTED: "First eligible observation in a new warm-up sequence.",
  PROVISIONAL_BASELINE: "Initial baseline exists with limited confidence.",
  WARMUP_INCONSISTENT: "Warm-up observations were not consistent enough to establish a baseline.",
  INSUFFICIENT_EVIDENCE: "There is not enough eligible activity to learn safely.",
  WITHIN_BAND: "Observed features stayed within the accepted deviation band.",
  HOST_DEVIATION: "Host features differ from the current baseline.",
  SEVERE_BASELINE_DEVIATION: "Observed host features are far outside the current baseline.",
  ADAPTATION_LIMIT_REACHED: "The baseline reached its cumulative anchor limit; learning is held.",
  PROBATION_ADMITTED: "Consistent low-risk probation observations permitted a guarded update.",
  NEW_PROTOCOL: "A protocol appeared that was absent from this host's baseline.",
  DUPLICATE_CAPTURE: "This capture was already evaluated; the baseline was not advanced.",
  OUT_OF_ORDER_CAPTURE: "The capture precedes a prior observation; learning is blocked.",
  OVERLAPPING_WINDOW: "The capture overlaps a prior observation; learning is blocked.",
  FLOW_OUTSIDE_TRAINING_RANGE: "Flow metadata lies outside the model's training range.",
  ML_HIGH: "A High-risk flow prevents baseline learning for this observation.",
  RULE_HIGH_EVIDENCE: "High rule evidence prevents baseline learning for the implicated host.",
  EXTREME_FLOW_EVIDENCE: "Extreme flow evidence prevents baseline learning.",
};
export function describeAdmissionReason(code: string): string {
  return reasons[code] ?? code.replaceAll("_", " ").toLowerCase() + ` (${code})`;
}
