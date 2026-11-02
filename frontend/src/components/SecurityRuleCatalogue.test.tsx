import {act} from "react";
import {createRoot} from "react-dom/client";
import {afterEach, expect, test} from "vitest";
import {SecurityRuleCatalogue} from "./SecurityRuleCatalogue";

Object.assign(globalThis, {IS_REACT_ACT_ENVIRONMENT: true});
let root: ReturnType<typeof createRoot>;
let container: HTMLDivElement;
afterEach(async () => {if (root) await act(async () => root.unmount()); container?.remove();});

test("opens and hides an accessible rule catalogue without any API action", async () => {
  container = document.createElement("div"); document.body.append(container); root = createRoot(container);
  await act(async () => root.render(<SecurityRuleCatalogue />));
  const button = container.querySelector<HTMLButtonElement>("button")!;
  expect(button.textContent).toBe("View Security Rules");
  expect(button.getAttribute("aria-expanded")).toBe("false");
  expect(button.getAttribute("aria-controls")).toBe("security-rule-catalogue");
  expect(container.querySelector("#security-rule-catalogue")?.hasAttribute("hidden")).toBe(true);
  button.focus();
  expect(document.activeElement).toBe(button);
  await act(async () => button.click());
  expect(button.getAttribute("aria-expanded")).toBe("true");
  expect(button.textContent).toBe("Hide Security Rules");
  const catalogue = container.querySelector("#security-rule-catalogue")!;
  expect(catalogue.textContent).toContain("R1 — Possible Port Sweep");
  expect(catalogue.textContent).toContain("R2 — Possible Host Reconnaissance");
  expect(catalogue.textContent).toContain("At least 6 TCP flows");
  expect(catalogue.textContent).toContain("At least 5 TCP flows or at least 5 UDP flows");
  expect(catalogue.textContent).toContain("min(90, 60 + 5 × (primary count − minimum count))");
  expect(catalogue.textContent).toContain("Rule Evidence Strength");
  expect(catalogue.textContent).toContain("Unknown");
  const conditions = catalogue.querySelector<HTMLDetailsElement>("details")!;
  await act(async () => conditions.querySelector("summary")!.click());
  expect(conditions.open).toBe(true);
  await act(async () => button.click());
  expect(button.getAttribute("aria-expanded")).toBe("false");
  expect(container.querySelector("#security-rule-catalogue")?.hasAttribute("hidden")).toBe(true);
});
