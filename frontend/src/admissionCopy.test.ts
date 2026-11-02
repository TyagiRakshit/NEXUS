import {expect, test} from "vitest";
import {describeAdmissionReason} from "./admissionCopy";
test("backend reason codes have plain language without hiding unknown codes", () => {
  expect(describeAdmissionReason("ADAPTATION_LIMIT_REACHED")).toContain("anchor");
  expect(describeAdmissionReason("SEVERE_BASELINE_DEVIATION")).toContain("far outside");
  expect(describeAdmissionReason("INSUFFICIENT_EVIDENCE")).toContain("enough");
  expect(describeAdmissionReason("FUTURE_REASON")).toContain("FUTURE_REASON");
});
