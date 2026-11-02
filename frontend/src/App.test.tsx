import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, test, vi } from "vitest";

type StatusBody = {
  overall_status: "healthy" | "degraded";
  services: {
    backend: "healthy";
    database: "healthy" | "unavailable";
  };
};

type AnalysisBody = {
  schema_version: "phase2.flow.v1";
  source: "REPLAYED DEMO TRAFFIC";
  fixture_id: "phase2-synthetic-v1";
  analysis_id: string;
  analyzed_at: string;
  packet_count: number;
  flow_count: number;
  flows: Array<{
    protocol: string;
    source_ip: string;
    source_port: number | null;
    destination_ip: string;
    destination_port: number | null;
    packet_count: number;
    byte_count: number;
    duration_seconds: number;
    packets_per_second: number;
    bytes_per_second: number;
  }>;
};

type ProfileBody = {
  schema_version: "phase3.profile.v1";
  source: "REPLAYED DEMO TRAFFIC";
  fixture_id: "phase3-normal-v1";
  interpretation: "NORMAL BASELINE ONLY - NO ANOMALY DECISION";
  analysis_id: string;
  analyzed_at: string;
  packet_count: number;
  flow_count: number;
  baseline_state: "warming" | "ready";
  warmup_required_batches: number;
  admitted_batch_count: number;
  window_batch_count: number;
  baseline_version: number;
  previous_baseline_version: number | null;
  hosts: Array<{
    host_ip: string;
    current_profile: {
      observed_flow_count: number;
      protocol_mix: Array<{ protocol: string; flow_count: number }>;
      average_bytes_per_flow: number;
      average_duration_seconds: number;
      average_packets_per_second: number;
    };
    baseline: null | {
      observed_batch_count: number;
      average_flow_count: number;
      protocol_mix: Array<{ protocol: string; average_flow_count: number }>;
      average_bytes_per_flow: number;
      average_duration_seconds: number;
      average_packets_per_second: number;
    };
  }>;
};

type DetectionBody = {
  schema_version: "phase4.detection.v1";
  source: "REPLAYED DEMO TRAFFIC";
  interpretation: "SYNTHETIC ANOMALY DEMO - STATISTICAL UNUSUALNESS, NOT MALICIOUS PROOF";
  training_fixture_id: "phase4-normal-train-v1";
  replay_fixture_id: "phase4-unusual-v1";
  analysis_id: string;
  analyzed_at: string;
  model: {
    model_type: "IsolationForest";
    model_version: "phase4-iforest-v1";
    random_seed: 42;
    training_flow_count: number;
    feature_count: 11;
    n_estimators: 100;
    max_samples: 32;
    model_threshold: number;
  };
  replay_packet_count: number;
  replay_flow_count: number;
  flagged_alert_count: number;
  results: Array<AnalysisBody["flows"][number] & {
    anomaly_score: number;
    is_statistically_unusual: boolean;
    risk_score: 20 | 60 | 90;
    risk_level: "Low" | "Medium" | "High";
    alert_flagged: boolean;
    explanations: string[];
  }>;
};

type UploadAnalysisBody = {
  schema_version: "demo.upload-analysis.v1";
  source: "REPLAYED DEMO TRAFFIC";
  interpretation: "STATISTICAL UNUSUALNESS RELATIVE TO SYNTHETIC TRAINING, NOT MALICIOUS PROOF";
  analysis_id: string;
  analyzed_at: string;
  packet_count: number;
  flow_count: number;
  flows: AnalysisBody["flows"];
  host_profiles: Array<{
    host_ip: string;
    observed_flow_count: number;
    protocol_mix: Array<{ protocol: string; flow_count: number }>;
    average_bytes_per_flow: number;
    average_duration_seconds: number;
    average_packets_per_second: number;
  }>;
  model: DetectionBody["model"];
  flagged_alert_count: number;
  results: DetectionBody["results"];
};

type ProtectBody = {
  schema_version: "phase5.secure-telemetry.v1";
  protection_id: string;
  analysis_id: string;
  status: "protected";
  aes_gcm: "protected";
  protected_count: number;
};

type VerifyBody = {
  schema_version: "phase5.secure-telemetry.v1";
  protection_id: string;
  analysis_id: string;
  verification: "verified";
  aes_gcm: "authenticated";
  sha256: "verified";
  rsa_pss: "valid";
  protected_count: number;
  verified_count: number;
  all_valid: true;
};

type TamperBody = {
  schema_version: "phase5.secure-telemetry.v1";
  protection_id: string;
  analysis_id: string;
  verification: "rejected";
  reason: "tamper_detected";
  protected_count: number;
  tamper_rejected: true;
};

const roots: Root[] = [];

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });

async function loadApp(): Promise<() => ReactNode> {
  try {
    return (await import("./App")).default;
  } catch {
    throw new Error("App is not implemented");
  }
}

async function renderApp(): Promise<HTMLElement> {
  const App = await loadApp();
  const container = document.createElement("div");
  document.body.append(container);
  const root = createRoot(container);
  roots.push(root);

  await act(async () => {
    root.render(<App />);
  });

  return container;
}

function response(body: StatusBody): Promise<Response> {
  return Promise.resolve({
    ok: true,
    json: async () => body,
  } as Response);
}

function jsonResponse(body: unknown): Promise<Response> {
  return Promise.resolve({
    ok: true,
    json: async () => body,
  } as Response);
}

function uploadAnalysisBody(): UploadAnalysisBody {
  const detection = detectionBody();
  return {
    schema_version: "demo.upload-analysis.v1",
    source: "REPLAYED DEMO TRAFFIC",
    interpretation:
      "STATISTICAL UNUSUALNESS RELATIVE TO SYNTHETIC TRAINING, NOT MALICIOUS PROOF",
    analysis_id: "de4165ae-e4ac-4436-b291-a99016292176",
    analyzed_at: "2026-10-05T09:15:00Z",
    packet_count: 16,
    flow_count: 3,
    flows: detection.results.map(
      ({
        anomaly_score: _anomalyScore,
        is_statistically_unusual: _isUnusual,
        risk_score: _riskScore,
        risk_level: _riskLevel,
        alert_flagged: _alertFlagged,
        explanations: _explanations,
        ...flow
      }) => flow,
    ),
    host_profiles: [
      {
        host_ip: "192.0.2.10",
        observed_flow_count: 3,
        protocol_mix: [
          { protocol: "ICMP", flow_count: 1 },
          { protocol: "TCP", flow_count: 1 },
          { protocol: "UDP", flow_count: 1 },
        ],
        average_bytes_per_flow: 648,
        average_duration_seconds: 1,
        average_packets_per_second: 12,
      },
    ],
    model: detection.model,
    flagged_alert_count: detection.flagged_alert_count,
    results: detection.results,
  };
}

const protectionId = "de4165ae-e4ac-4436-b291-a99016292176";

function protectBody(): ProtectBody {
  return {
    schema_version: "phase5.secure-telemetry.v1",
    protection_id: protectionId,
    analysis_id: protectionId,
    status: "protected",
    aes_gcm: "protected",
    protected_count: 1,
  };
}

function verifyBody(): VerifyBody {
  return {
    schema_version: "phase5.secure-telemetry.v1",
    protection_id: protectionId,
    analysis_id: protectionId,
    verification: "verified",
    aes_gcm: "authenticated",
    sha256: "verified",
    rsa_pss: "valid",
    protected_count: 1,
    verified_count: 1,
    all_valid: true,
  };
}

function tamperBody(): TamperBody {
  return {
    schema_version: "phase5.secure-telemetry.v1",
    protection_id: protectionId,
    analysis_id: protectionId,
    verification: "rejected",
    reason: "tamper_detected",
    protected_count: 1,
    tamper_rejected: true,
  };
}

function detectionBody(): DetectionBody {
  const baseFlow = {
    source_ip: "192.0.2.10",
    source_port: 56001,
    destination_ip: "198.51.100.20",
    destination_port: 443,
    packet_count: 12,
    byte_count: 648,
    duration_seconds: 1,
    packets_per_second: 12,
    bytes_per_second: 648,
  };
  return {
    schema_version: "phase4.detection.v1",
    source: "REPLAYED DEMO TRAFFIC",
    interpretation:
      "SYNTHETIC ANOMALY DEMO - STATISTICAL UNUSUALNESS, NOT MALICIOUS PROOF",
    training_fixture_id: "phase4-normal-train-v1",
    replay_fixture_id: "phase4-unusual-v1",
    analysis_id: "4c98d39b-b301-4a99-b418-77c8e1e39872",
    analyzed_at: "2026-10-04T18:30:00Z",
    model: {
      model_type: "IsolationForest",
      model_version: "phase4-iforest-v1",
      random_seed: 42,
      training_flow_count: 48,
      feature_count: 11,
      n_estimators: 100,
      max_samples: 32,
      model_threshold: 0.5,
    },
    replay_packet_count: 16,
    replay_flow_count: 3,
    flagged_alert_count: 1,
    results: [
      {
        ...baseFlow,
        protocol: "TCP",
        anomaly_score: 0.49,
        is_statistically_unusual: false,
        risk_score: 20,
        risk_level: "Low",
        alert_flagged: false,
        explanations: ["No metadata feature is outside the synthetic training range."],
      },
      {
        ...baseFlow,
        protocol: "UDP",
        source_port: 56002,
        anomaly_score: 0.52,
        is_statistically_unusual: true,
        risk_score: 60,
        risk_level: "Medium",
        alert_flagged: false,
        explanations: ["Duration seconds is above the synthetic training range."],
      },
      {
        ...baseFlow,
        protocol: "ICMP",
        source_port: null,
        destination_port: null,
        anomaly_score: 0.61167,
        is_statistically_unusual: true,
        risk_score: 90,
        risk_level: "High",
        alert_flagged: true,
        explanations: [
          "Protocol ICMP was not present in the synthetic training fixture.",
          "Port-presence pattern was not present in the synthetic training fixture.",
        ],
      },
    ],
  };
}

function profileBody(state: "warming" | "ready"): ProfileBody {
  const ready = state === "ready";
  return {
    schema_version: "phase3.profile.v1",
    source: "REPLAYED DEMO TRAFFIC",
    fixture_id: "phase3-normal-v1",
    interpretation: "NORMAL BASELINE ONLY - NO ANOMALY DECISION",
    analysis_id: "6267bbbe-3cd0-4c76-adf6-c13ee45476cd",
    analyzed_at: "2026-10-04T14:30:00Z",
    packet_count: 16,
    flow_count: 8,
    baseline_state: state,
    warmup_required_batches: 2,
    admitted_batch_count: ready ? 2 : 1,
    window_batch_count: ready ? 2 : 1,
    baseline_version: ready ? 1 : 0,
    previous_baseline_version: null,
    hosts: [
      {
        host_ip: "192.0.2.10",
        current_profile: {
          observed_flow_count: 6,
          protocol_mix: [
            { protocol: "ICMP", flow_count: 1 },
            { protocol: "TCP", flow_count: 3 },
            { protocol: "UDP", flow_count: 2 },
          ],
          average_bytes_per_flow: 96,
          average_duration_seconds: 2.333,
          average_packets_per_second: 1.167,
        },
        baseline: ready
          ? {
              observed_batch_count: 2,
              average_flow_count: 6,
              protocol_mix: [
                { protocol: "ICMP", average_flow_count: 1 },
                { protocol: "TCP", average_flow_count: 3 },
                { protocol: "UDP", average_flow_count: 2 },
              ],
              average_bytes_per_flow: 96,
              average_duration_seconds: 2.333,
              average_packets_per_second: 1.167,
            }
          : null,
      },
    ],
  };
}

function button(container: HTMLElement, name: string): HTMLButtonElement {
  const match = [...container.querySelectorAll("button")].find(
    (element) => element.textContent === name,
  );
  if (!(match instanceof HTMLButtonElement)) {
    throw new Error(`Missing ${name} button`);
  }
  return match;
}

function card(container: HTMLElement, name: string): HTMLElement {
  const match = [...container.querySelectorAll("article")].find(
    (element) => element.querySelector("h2")?.textContent === name,
  );
  if (!(match instanceof HTMLElement)) {
    throw new Error(`Missing ${name} card`);
  }
  return match;
}

function pcapInput(container: HTMLElement): HTMLInputElement {
  const match = container.querySelector("input[type='file']");
  if (!(match instanceof HTMLInputElement)) {
    throw new Error("Missing PCAP file input");
  }
  return match;
}

async function chooseFile(input: HTMLInputElement, file: File): Promise<void> {
  await act(async () => {
    Object.defineProperty(input, "files", {
      configurable: true,
      value: [file],
    });
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
}

afterEach(async () => {
  await act(async () => {
    roots.splice(0).forEach((root) => root.unmount());
  });
  document.body.replaceChildren();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("service dashboard", () => {
  test("shows exactly three initial cards and makes one status request", async () => {
    const fetchMock = vi.fn(() => new Promise<Response>(() => {}));
    vi.stubGlobal("fetch", fetchMock);

    const container = await renderApp();

    expect(container.querySelectorAll("article")).toHaveLength(3);
    expect(card(container, "Frontend").textContent).toContain("Healthy");
    expect(card(container, "Backend").textContent).toContain("Checking");
    expect(card(container, "Database").textContent).toContain("Checking");
    expect(container.querySelector("[role='status']")?.textContent).toBe(
      "Checking...",
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/status");
  });

  test("shows the local PCAP picker with analysis disabled initially", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        response({
          overall_status: "healthy",
          services: { backend: "healthy", database: "healthy" },
        }),
      ),
    );

    const container = await renderApp();
    const section = container.querySelector(".network-data-picker");

    expect(section?.textContent).toContain("Analyze network data");
    expect(section?.textContent).not.toContain("REPLAYED DEMO TRAFFIC");
    expect(section?.textContent).not.toContain("Choose a local synthetic .pcap file");
    expect(section?.textContent).not.toContain("Offline PCAP analysis on the local NEXUS backend");
    expect(container.querySelector('section[aria-label="Analysis summary"]')).toBeNull();
    expect(container.querySelector("#network-data-help")).toBeNull();
    expect(pcapInput(container).accept).toBe(".pcap");
    expect(button(container, "Analyze network data").disabled).toBe(true);
  });

  test("shows valid file details and enables analysis", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        response({
          overall_status: "healthy",
          services: { backend: "healthy", database: "healthy" },
        }),
      ),
    );
    const container = await renderApp();

    await chooseFile(
      pcapInput(container),
      new File([new Uint8Array(512)], "synthetic-demo.pcap"),
    );

    const section = container.querySelector(".network-data-picker");
    expect(section?.textContent).toContain("synthetic-demo.pcap");
    expect(section?.textContent).toContain("512 bytes");
    expect(button(container, "Analyze network data").disabled).toBe(false);
  });

  test("rejects a non-PCAP file and keeps analysis disabled", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        response({
          overall_status: "healthy",
          services: { backend: "healthy", database: "healthy" },
        }),
      ),
    );
    const container = await renderApp();

    await chooseFile(
      pcapInput(container),
      new File([new Uint8Array(32)], "notes.txt"),
    );

    const section = container.querySelector(".network-data-picker");
    expect(section?.querySelector("[role='alert']")?.textContent).toBe(
      "Choose a .pcap file.",
    );
    expect(button(container, "Analyze network data").disabled).toBe(true);
  });

  test("rejects a PCAP larger than 1 MiB and keeps analysis disabled", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        response({
          overall_status: "healthy",
          services: { backend: "healthy", database: "healthy" },
        }),
      ),
    );
    const container = await renderApp();

    await chooseFile(
      pcapInput(container),
      new File([new Uint8Array(1_048_577)], "oversize.pcap"),
    );

    const section = container.querySelector(".network-data-picker");
    expect(section?.querySelector("[role='alert']")?.textContent).toBe(
      "PCAP files must be 1 MiB or smaller.",
    );
    expect(button(container, "Analyze network data").disabled).toBe(true);
  });

  test("sends one multipart file request and shows the pending state", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    let resolveUpload: (value: Response) => void = () => {};
    const pendingUpload = new Promise<Response>((resolve) => {
      resolveUpload = resolve;
    });
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => pendingUpload);
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();
    const file = new File([new Uint8Array(256)], "ready.pcap");

    await chooseFile(pcapInput(container), file);
    await act(async () => {
      button(container, "Analyze network data").click();
      await Promise.resolve();
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [url, options] = fetchMock.mock.calls[1] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe("/api/v1/demo/upload/analyze");
    expect(options.method).toBe("POST");
    expect(options.body).toBeInstanceOf(FormData);
    const entries = [...(options.body as FormData).entries()];
    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual(["file", file]);
    expect(button(container, "Analyzing network data...").disabled).toBe(true);

    await act(async () => {
      resolveUpload({
        ok: true,
        json: async () => uploadAnalysisBody(),
      } as Response);
      await pendingUpload;
      await Promise.resolve();
    });
  });

  test("renders uploaded metadata, profiles, and backend decisions without removing existing sections", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(uploadAnalysisBody()));
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await chooseFile(
      pcapInput(container),
      new File([new Uint8Array(256)], "phase4-unusual.pcap"),
    );
    await act(async () => {
      button(container, "Analyze network data").click();
      await Promise.resolve();
    });

    const uploaded = container.querySelector(".uploaded-network-analysis");
    expect(uploaded?.textContent).toContain("Uploaded network analysis");
    expect(uploaded?.textContent).not.toContain("REPLAYED DEMO TRAFFIC");
    expect(uploaded?.textContent).toContain("phase4-unusual.pcap");
    expect(uploaded?.textContent).toContain("16 packets | 3 flows");
    expect(uploaded?.textContent).toContain("192.0.2.10:56001");
    expect(uploaded?.textContent).toContain("ICMP 1, TCP 1, UDP 1");
    expect(uploaded?.textContent).toContain("0.611670");
    expect(uploaded?.textContent).toContain("High");
    expect(uploaded?.textContent).toContain(
      "Protocol ICMP was not present in the synthetic training fixture.",
    );
    expect(uploaded?.textContent).toContain("1 flagged alert");
    expect(uploaded?.textContent?.match(/ALERT FLAGGED/g)).toHaveLength(1);
    expect(container.querySelectorAll("article")).toHaveLength(3);
    expect(button(container, "Analyze offline fixture")).toBeTruthy();
    expect(button(container, "Build/update normal baseline")).toBeTruthy();
    expect(button(container, "Run anomaly replay")).toBeTruthy();
  });

  test("keeps upload primary and collapses all optional replay controls initially", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        response({
          overall_status: "healthy",
          services: { backend: "healthy", database: "healthy" },
        }),
      ),
    );

    const container = await renderApp();
    const upload = container.querySelector(".network-data-picker");
    const advanced = container.querySelector("details.advanced-replay-controls");
    const summary = advanced?.querySelector("summary");

    expect(upload).toBeTruthy();
    expect(advanced).toBeInstanceOf(HTMLDetailsElement);
    expect((advanced as HTMLDetailsElement | null)?.open).toBe(false);
    expect(summary?.textContent).toBe("Advanced replay controls (optional)");
    expect(upload?.compareDocumentPosition(advanced as Node)).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
    expect(advanced?.querySelector(".replay-analysis")).toBeTruthy();
    expect(advanced?.querySelector(".profile-baseline")).toBeTruthy();
    expect(advanced?.querySelector(".anomaly-detection")).toBeTruthy();
    expect(container.querySelectorAll("article")).toHaveLength(3);
  });

  test("uses plain-text separators and directions in uploaded results", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(uploadAnalysisBody()));
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await chooseFile(
      pcapInput(container),
      new File([new Uint8Array(256)], "phase4-unusual.pcap"),
    );
    await act(async () => {
      button(container, "Analyze network data").click();
      await Promise.resolve();
    });

    const visibleText = container.textContent ?? "";
    expect(visibleText).toContain("16 packets | 3 flows");
    expect(visibleText).toContain("TCP 192.0.2.10:56001 to 198.51.100.20:443");
    expect(visibleText).not.toContain("â");
  });

  test.each([
    ["non-200", { ok: false, json: async () => ({ detail: "private" }) }],
    ["malformed", { ok: true, json: async () => ({ flow_count: "private" }) }],
  ])("shows a safe %s upload error and clears the prior actionable analysis", async (_case, failure) => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(uploadAnalysisBody()))
      .mockImplementationOnce(() => Promise.resolve(failure as Response));
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await chooseFile(
      pcapInput(container),
      new File([new Uint8Array(256)], "phase4-unusual.pcap"),
    );
    await act(async () => {
      button(container, "Analyze network data").click();
      await Promise.resolve();
    });
    await act(async () => {
      button(container, "Analyze network data").click();
      await Promise.resolve();
    });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(container.querySelector(".network-data-picker")?.textContent).toContain(
      "Unable to analyze selected PCAP.",
    );
    expect(container.querySelector(".uploaded-network-analysis")).toBeNull();
    expect(container.textContent).not.toContain("private");
  });

  test("shows secure telemetry controls only for a flagged uploaded result", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    const withoutFlag = uploadAnalysisBody();
    withoutFlag.flagged_alert_count = 0;
    withoutFlag.results = withoutFlag.results.map((result) => ({
      ...result,
      is_statistically_unusual: false,
      risk_score: 20,
      risk_level: "Low",
      alert_flagged: false,
    }));
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(withoutFlag));
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    expect(container.textContent).not.toContain("Protect all flagged alerts");
    await chooseFile(
      pcapInput(container),
      new File([new Uint8Array(256)], "normal.pcap"),
    );
    await act(async () => {
      button(container, "Analyze network data").click();
      await Promise.resolve();
    });

    expect(container.textContent).toContain("Uploaded network analysis");
    expect(container.textContent).not.toContain("Protect all flagged alerts");
  });

  test("protects and verifies all flagged alerts with one safe request per click", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    let resolveProtection: (value: Response) => void = () => {};
    const pendingProtection = new Promise<Response>((resolve) => {
      resolveProtection = resolve;
    });
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(uploadAnalysisBody()))
      .mockImplementationOnce(() => pendingProtection)
      .mockImplementationOnce(() => jsonResponse(verifyBody()))
      .mockImplementationOnce(() => jsonResponse(tamperBody()));
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await chooseFile(
      pcapInput(container),
      new File([new Uint8Array(256)], "phase4-mixed-demo.pcap"),
    );
    await act(async () => {
      button(container, "Analyze network data").click();
      await Promise.resolve();
    });
    expect(button(container, "Protect all flagged alerts")).toBeTruthy();

    await act(async () => {
      button(container, "Protect all flagged alerts").click();
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      "/api/v1/demo/telemetry/protect",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysis_id: uploadAnalysisBody().analysis_id }),
      },
    );
    expect(button(container, "Protecting...").disabled).toBe(true);

    await act(async () => {
      resolveProtection({ ok: true, json: async () => protectBody() } as Response);
      await pendingProtection;
      await Promise.resolve();
    });
    expect(container.textContent).toContain("AES-GCM protected");
    expect(container.textContent).toContain("1 flagged alerts protected");

    await act(async () => {
      button(container, "Verify protected alerts").click();
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenNthCalledWith(
      4,
      `/api/v1/demo/telemetry/${protectionId}/verify`,
      { method: "POST" },
    );
    expect(container.textContent).toContain("All SHA-256 digests verified");
    expect(container.textContent).toContain("All RSA signatures valid");
    expect(container.textContent).toContain("1/1 alerts verified");
    expect(container.textContent).toContain("All RSA signatures valid");
    expect(container.textContent).toContain("All SHA-256 digests verified");

    await act(async () => {
      button(container, "Verify tampered copy").click();
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenNthCalledWith(
      5,
      `/api/v1/demo/telemetry/${protectionId}/verify-tampered`,
      { method: "POST" },
    );
    expect(container.textContent).toContain("Tampered copy rejected");
    expect(container.textContent).toContain("Uploaded network analysis");
    expect(container.textContent).toContain("16 packets | 3 flows");
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  test("keeps upload results on safe crypto error and resets crypto after a new upload", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    const malformedSecretResponse = {
      ...protectBody(),
      ciphertext: "must-never-render",
    };
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(uploadAnalysisBody()))
      .mockImplementationOnce(() => jsonResponse(malformedSecretResponse))
      .mockImplementationOnce(() => jsonResponse(protectBody()))
      .mockImplementationOnce(() => jsonResponse(uploadAnalysisBody()));
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();
    const file = new File([new Uint8Array(256)], "phase4-mixed-demo.pcap");

    await chooseFile(pcapInput(container), file);
    await act(async () => {
      button(container, "Analyze network data").click();
      await Promise.resolve();
    });
    await act(async () => {
      button(container, "Protect all flagged alerts").click();
      await Promise.resolve();
    });
    expect(container.textContent).toContain("Unable to protect flagged alerts.");
    expect(container.textContent).not.toContain("must-never-render");
    expect(container.textContent).toContain("Uploaded network analysis");

    await act(async () => {
      button(container, "Protect all flagged alerts").click();
      await Promise.resolve();
    });
    expect(container.textContent).toContain("AES-GCM protected");

    await act(async () => {
      button(container, "Analyze network data").click();
      await Promise.resolve();
    });
    expect(container.textContent).not.toContain("AES-GCM protected");
    expect(button(container, "Protect all flagged alerts")).toBeTruthy();
  });

  test("shows the labelled offline replay action without adding a status card", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        response({
          overall_status: "healthy",
          services: { backend: "healthy", database: "healthy" },
        }),
      ),
    );

    const container = await renderApp();

    expect(container.querySelectorAll("article")).toHaveLength(3);
    expect(container.textContent).toContain("REPLAYED DEMO TRAFFIC");
    expect(button(container, "Analyze offline fixture")).toBeTruthy();
    expect(container.querySelector("table")).toBeNull();
  });

  test("makes one analysis request per click and renders the flow table", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    const analysis: AnalysisBody = {
      schema_version: "phase2.flow.v1",
      source: "REPLAYED DEMO TRAFFIC",
      fixture_id: "phase2-synthetic-v1",
      analysis_id: "7876a270-3cb2-41cd-b1c1-03472e6d4f71",
      analyzed_at: "2026-10-04T13:38:52.570945Z",
      packet_count: 7,
      flow_count: 3,
      flows: [
        {
          protocol: "TCP",
          source_ip: "192.0.2.10",
          source_port: 51515,
          destination_ip: "198.51.100.20",
          destination_port: 443,
          packet_count: 3,
          byte_count: 162,
          duration_seconds: 2,
          packets_per_second: 1.5,
          bytes_per_second: 81,
        },
        {
          protocol: "UDP",
          source_ip: "2001:db8::10",
          source_port: 53000,
          destination_ip: "2001:db8::20",
          destination_port: 53001,
          packet_count: 2,
          byte_count: 124,
          duration_seconds: 1,
          packets_per_second: 2,
          bytes_per_second: 124,
        },
        {
          protocol: "ICMP",
          source_ip: "192.0.2.10",
          source_port: null,
          destination_ip: "198.51.100.20",
          destination_port: null,
          packet_count: 2,
          byte_count: 84,
          duration_seconds: 1,
          packets_per_second: 2,
          bytes_per_second: 84,
        },
      ],
    };
    let resolveAnalysis: (value: Response) => void = () => {};
    const pendingAnalysis = new Promise<Response>((resolve) => {
      resolveAnalysis = resolve;
    });
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => pendingAnalysis);
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await act(async () => {
      button(container, "Analyze offline fixture").click();
      await Promise.resolve();
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenNthCalledWith(2, "/api/v1/demo/flows/analyze", {
      method: "POST",
    });
    expect(button(container, "Analyzing...").disabled).toBe(true);

    await act(async () => {
      resolveAnalysis({ ok: true, json: async () => analysis } as Response);
      await pendingAnalysis;
      await Promise.resolve();
    });

    expect(container.textContent).toContain("7 packets | 3 flows");
    expect(container.querySelectorAll("tbody tr")).toHaveLength(3);
    expect(container.textContent).toContain("192.0.2.10:51515");
    expect(container.textContent).toContain("198.51.100.20:443");
    expect(container.textContent).toContain("192.0.2.10:-");
    expect(container.textContent).toContain("2.000");
    expect(container.textContent).toContain("81.000");
  });

  test("shows a short analysis error without changing the status cards", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockRejectedValueOnce(new Error("private parser detail"));
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await act(async () => {
      button(container, "Analyze offline fixture").click();
      await Promise.resolve();
    });

    expect(container.querySelectorAll("article")).toHaveLength(3);
    expect(card(container, "Backend").textContent).toContain("Healthy");
    expect(container.textContent).toContain("Unable to analyze offline fixture.");
    expect(container.textContent).not.toContain("private parser detail");
  });

  test("shows the normal baseline action and exact honesty labels without adding cards", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        response({
          overall_status: "healthy",
          services: { backend: "healthy", database: "healthy" },
        }),
      ),
    );

    const container = await renderApp();

    expect(container.querySelectorAll("article")).toHaveLength(3);
    expect(container.textContent).toContain("REPLAYED DEMO TRAFFIC");
    expect(container.textContent).toContain(
      "NORMAL BASELINE ONLY - NO ANOMALY DECISION",
    );
    expect(button(container, "Analyze offline fixture")).toBeTruthy();
    expect(button(container, "Build/update normal baseline")).toBeTruthy();
  });

  test("makes one profile request per click and renders the warming profile", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    let resolveProfile: (value: Response) => void = () => {};
    const pendingProfile = new Promise<Response>((resolve) => {
      resolveProfile = resolve;
    });
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => pendingProfile);
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await act(async () => {
      button(container, "Build/update normal baseline").click();
      await Promise.resolve();
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenNthCalledWith(2, "/api/v1/demo/profiles/adapt", {
      method: "POST",
    });
    expect(button(container, "Building baseline...").disabled).toBe(true);

    await act(async () => {
      resolveProfile({
        ok: true,
        json: async () => profileBody("warming"),
      } as Response);
      await pendingProfile;
      await Promise.resolve();
    });

    const section = container.querySelector(".profile-baseline");
    expect(section?.textContent).toContain("Warm-up: 1 of 2 batches");
    expect(section?.textContent).toContain("192.0.2.10");
    expect(section?.textContent).toContain("ICMP 1, TCP 3, UDP 2");
    expect(section?.textContent).toContain("96.000");
    expect(section?.textContent).toContain("2.333");
    expect(section?.textContent).toContain("1.167");
    expect(section?.textContent).toContain("Not ready");
  });

  test("renders ready baseline values and the unchanged-values limitation", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(profileBody("ready")));
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await act(async () => {
      button(container, "Build/update normal baseline").click();
      await Promise.resolve();
    });

    const section = container.querySelector(".profile-baseline");
    expect(section?.textContent).toContain(
      "Baseline v1 | 2 admitted batches | 2 in window",
    );
    expect(section?.textContent).toContain("6.000");
    expect(section?.textContent).toContain(
      "Repeated requests replay identical normal data, so unchanged values are not evidence of real-world adaptive learning.",
    );
    expect(section?.textContent).not.toContain("risk score");
    expect(section?.textContent).not.toContain("prediction");
  });

  test("shows a short baseline error without changing cards or Phase 2 action", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockRejectedValueOnce(new Error("private profile path"));
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await act(async () => {
      button(container, "Build/update normal baseline").click();
      await Promise.resolve();
    });

    expect(container.querySelectorAll("article")).toHaveLength(3);
    expect(button(container, "Analyze offline fixture")).toBeTruthy();
    expect(container.textContent).toContain("Unable to update normal baseline.");
    expect(container.textContent).not.toContain("private profile path");
  });

  test("shows the synthetic anomaly action and exact honesty labels without changing earlier sections", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        response({
          overall_status: "healthy",
          services: { backend: "healthy", database: "healthy" },
        }),
      ),
    );

    const container = await renderApp();
    const section = container.querySelector(".anomaly-detection");

    expect(container.querySelectorAll("article")).toHaveLength(3);
    expect(button(container, "Analyze offline fixture")).toBeTruthy();
    expect(button(container, "Build/update normal baseline")).toBeTruthy();
    expect(button(container, "Run anomaly replay")).toBeTruthy();
    expect(section?.textContent).toContain("REPLAYED DEMO TRAFFIC");
    expect(section?.textContent).toContain(
      "SYNTHETIC ANOMALY DEMO - STATISTICAL UNUSUALNESS, NOT MALICIOUS PROOF",
    );
    expect(section?.textContent).toContain("Synthetic anomaly replay");
  });

  test("makes one detection request and displays model scores separately from risk decisions", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    let resolveDetection: (value: Response) => void = () => {};
    const pendingDetection = new Promise<Response>((resolve) => {
      resolveDetection = resolve;
    });
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockImplementationOnce(() => pendingDetection);
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await act(async () => {
      button(container, "Run anomaly replay").click();
      await Promise.resolve();
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "/api/v1/demo/detection/analyze",
      { method: "POST" },
    );
    expect(button(container, "Detecting...").disabled).toBe(true);

    await act(async () => {
      resolveDetection({ ok: true, json: async () => detectionBody() } as Response);
      await pendingDetection;
      await Promise.resolve();
    });

    const section = container.querySelector(".anomaly-detection");
    expect(section?.textContent).toContain(
      "IsolationForest | model phase4-iforest-v1 | seed 42 | 48 training flows",
    );
    expect(section?.textContent).toContain("3 scored flows | 1 flagged alert");
    expect(section?.textContent).toContain("Score");
    expect(section?.textContent).toContain("Risk score");
    expect(section?.textContent).toContain("0.611670");
    expect(section?.textContent).toContain("90");
    expect(section?.textContent).toContain("Low");
    expect(section?.textContent).toContain("Medium");
    expect(section?.textContent).toContain("High");
    expect(section?.textContent?.match(/ALERT FLAGGED/g)).toHaveLength(1);
    expect(section?.textContent?.match(/Not flagged/g)).toHaveLength(2);
    expect(section?.textContent).toContain(
      "Protocol ICMP was not present in the synthetic training fixture.",
    );
    expect(section?.textContent).toContain(
      "Statistical unusualness in synthetic replay data is not proof of malicious activity.",
    );
  });

  test("shows a short detection error without changing cards or earlier actions", async () => {
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    const fetchMock = vi
      .fn(() => jsonResponse(healthy))
      .mockImplementationOnce(() => jsonResponse(healthy))
      .mockRejectedValueOnce(new Error("private model path"));
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();

    await act(async () => {
      button(container, "Run anomaly replay").click();
      await Promise.resolve();
    });

    expect(container.querySelectorAll("article")).toHaveLength(3);
    expect(button(container, "Analyze offline fixture")).toBeTruthy();
    expect(button(container, "Build/update normal baseline")).toBeTruthy();
    expect(container.textContent).toContain("Unable to run synthetic anomaly replay.");
    expect(container.textContent).not.toContain("private model path");
  });

  test.each([
    [
      "healthy",
      {
        overall_status: "healthy",
        services: { backend: "healthy", database: "healthy" },
      } satisfies StatusBody,
      "Healthy",
    ],
    [
      "degraded",
      {
        overall_status: "degraded",
        services: { backend: "healthy", database: "unavailable" },
      } satisfies StatusBody,
      "Unavailable",
    ],
  ])("renders the %s service response", async (_name, body, databaseText) => {
    vi.stubGlobal("fetch", vi.fn(() => response(body)));

    const container = await renderApp();

    expect(card(container, "Backend").textContent).toContain("Healthy");
    expect(card(container, "Database").textContent).toContain(databaseText);
    expect(container.querySelector("[role='status']")?.textContent).toMatch(
      /^Last checked: .+/,
    );
  });

  test("shows truthful states when the status request fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    const container = await renderApp();

    expect(card(container, "Backend").textContent).toContain("Unavailable");
    expect(card(container, "Database").textContent).toContain("Unknown");
    expect(container.querySelector("[role='alert']")?.textContent).toBe(
      "Unable to load service status.",
    );
  });

  test("makes exactly one additional request when Refresh is pressed", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2026, 9, 4, 10, 15, 30));
    const healthy: StatusBody = {
      overall_status: "healthy",
      services: { backend: "healthy", database: "healthy" },
    };
    let resolveRefresh: (value: Response) => void = () => {};
    const refreshResponse = new Promise<Response>((resolve) => {
      resolveRefresh = resolve;
    });
    const fetchMock = vi
      .fn(() => response(healthy))
      .mockImplementationOnce(() => response(healthy))
      .mockImplementationOnce(() => refreshResponse);
    vi.stubGlobal("fetch", fetchMock);
    const container = await renderApp();
    const initialFeedback = container.querySelector("[role='status']")?.textContent;

    expect(initialFeedback).toMatch(/^Last checked: .+/);
    vi.setSystemTime(new Date(2026, 9, 4, 10, 16, 45));

    await act(async () => {
      button(container, "Refresh").dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(container.querySelector("[role='status']")?.textContent).toBe(
      "Checking...",
    );

    await act(async () => {
      resolveRefresh({ ok: true, json: async () => healthy } as Response);
      await refreshResponse;
      await Promise.resolve();
    });

    const refreshedFeedback = container.querySelector("[role='status']")?.textContent;
    expect(refreshedFeedback).toMatch(/^Last checked: .+/);
    expect(refreshedFeedback).not.toBe(initialFeedback);
  });
});
test("dashboard defaults to Overview Summary and keeps service state when navigating", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response({overall_status: "healthy", services: {backend: "healthy", database: "healthy"}})));
  const container = await renderApp();
  expect(container.querySelector('[aria-current="page"]')?.textContent).toContain("Overview");
  expect(container.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toContain("Summary");
  await act(async () => container.querySelector<HTMLButtonElement>('[aria-label="System Status"]')!.click());
  expect(container.querySelector('[aria-current="page"]')?.textContent).toContain("System Status");
  expect(container.querySelector(".service-grid")?.closest("[hidden]")).toBeNull();
  await act(async () => container.querySelector<HTMLButtonElement>('[aria-label="Adaptive Baseline"]')!.click());
  expect(container.querySelector(".service-grid")?.closest("[hidden]")).not.toBeNull();
  expect(container.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toContain("Evolution");
});
test("flow explorer filters uploaded metadata without changing original ML results", async () => {
  const healthy: StatusBody = {overall_status:"healthy", services:{backend:"healthy", database:"healthy"}};
  vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce({ok:true,json:async()=>healthy}).mockResolvedValueOnce({ok:true,json:async()=>uploadAnalysisBody()}));
  const container=await renderApp();
  await chooseFile(pcapInput(container), new File([new Uint8Array(256)], "phase4-unusual.pcap"));
  await act(async () => {button(container,"Analyze network data").click(); await Promise.resolve();});
  await act(async () => container.querySelector<HTMLButtonElement>('[aria-label="Traffic Analysis"]')!.click());
  await act(async () => [...container.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find(b=>b.textContent==="Flow Explorer")!.click());
  const filter=container.querySelector<HTMLInputElement>('input[aria-label="Filter uploaded flows"]')!;
  expect(container.querySelectorAll("#uploaded-flow-table tbody tr")).toHaveLength(3);
  await act(async () => {Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(filter, "ICMP"); filter.dispatchEvent(new Event("input",{bubbles:true}));});
  expect(container.querySelectorAll("#uploaded-flow-table tbody tr")).toHaveLength(1);
  expect(container.querySelectorAll(".uploaded-network-analysis .alert-row")).toHaveLength(1);
});
test("Recent Analysis hides the upload card instead of leaving an empty panel", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response({overall_status:"healthy", services:{backend:"healthy",database:"healthy"}})));
  const container=await renderApp();
  await act(async () => [...container.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find(b=>b.textContent==="Recent Analysis")!.click());
  expect(container.querySelector(".network-data-picker")?.hasAttribute("hidden")).toBe(true);
  expect(container.textContent).toContain("Current browser session only");
});
test("Rules tab exposes the catalogue before upload without making a detection request", async () => {
  const fetchMock = vi.fn(() => response({overall_status:"healthy",services:{backend:"healthy",database:"healthy"}}));
  vi.stubGlobal("fetch", fetchMock);
  const container = await renderApp();
  await act(async () => container.querySelector<HTMLButtonElement>('[aria-label="Security Findings"]')!.click());
  await act(async () => [...container.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find(button => button.textContent === "Rules")!.click());
  const toggle = button(container, "View Security Rules");
  expect(toggle.getAttribute("aria-expanded")).toBe("false");
  await act(async () => toggle.click());
  expect(container.textContent).toContain("R1 — Possible Port Sweep");
  expect(fetchMock).toHaveBeenCalledTimes(1);
});
