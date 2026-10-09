/** Upear product overlay on the CE-compatible SUMC tree. */
export const PRODUCT_EDITION = 'upear' as const;
export const PRODUCT_NAME = 'Upear';
export const PRODUCT_UI_NAME = 'Upear UI';
export const PRODUCT_UI_ID = 'Upear_ui';
export const IS_COMMUNITY_EDITION_BUILD = true;
export const IS_SAFEHARNESS_EDITION_BUILD = true;
export const HELP_DOCUMENTATION_URL = 'https://github.com/ZJU-REAL/HugAgentOS';

/**
 * Static Upear baseline. Backend capability discovery may narrow this set;
 * components and stores stay in the tree while unsupported entry points remain hidden.
 */
export const SAFEHARNESS_CAPABILITIES = Object.freeze({
  chat: true,
  agents: true,
  kb: true,
  app_center: true,
  projects: true,
  project_detail: true,
  my_space: true,
  settings: true,
  ability_center: true,
  skills: true,
  mcp: true,
  lab: false,
  docs: false,
  share_records: false,
  protected_chat: false,
  security_operations: true,
  capability_writes: false,
  application_execution: false,
});

export type SafeHarnessCapability = keyof typeof SAFEHARNESS_CAPABILITIES;

export function isSafeHarnessCapabilityEnabled(capability: string): boolean {
  if (!IS_SAFEHARNESS_EDITION_BUILD) return true;
  return SAFEHARNESS_CAPABILITIES[capability as keyof typeof SAFEHARNESS_CAPABILITIES] === true;
}
