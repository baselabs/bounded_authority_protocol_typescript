// The CSP red-proof page: it calls eval, which the strict CSP (no 'unsafe-eval') must block, and the
// same securitypolicyviolation listener the lane page uses must record it.
const violations: string[] = [];
document.addEventListener("securitypolicyviolation", (e) => violations.push(`${e.violatedDirective} ${e.blockedURI}`));

let evalBlocked = false;
try {
  (0, eval)("1 + 1");
} catch {
  evalBlocked = true;
}
// The violation event is dispatched asynchronously; publish after it has had a chance to arrive.
setTimeout(() => {
  (window as unknown as { __BAP_PROBE__: unknown }).__BAP_PROBE__ = { evalBlocked, violations };
  document.body.dataset.state = "done";
}, 250);
