import {renderToStaticMarkup} from "react-dom/server";
import {expect, test} from "vitest";
import {TelemetryPanel} from "./TelemetryPanel";
import type {UploadAnalysisResponse} from "../status";
test("v2 copy directs users to the separate v1 tab", () => {
  const upload={analysis_id:"a",flagged_alert_count:1} as UploadAnalysisResponse;
  const html=renderToStaticMarkup(<TelemetryPanel upload={upload} hybrid={null} />);
  expect(html).toContain("their own tab");
  expect(html).not.toContain("controls below");
});
