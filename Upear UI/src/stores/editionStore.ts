import { create } from 'zustand';
import { PRODUCT_EDITION, SAFEHARNESS_CAPABILITIES } from '../edition';
import { discoverSafeHarnessCapabilities } from '../safeharnessApi';

interface CommunityEditionState {
  edition: 'ce';
  mode: 'ce';
  productEdition: typeof PRODUCT_EDITION;
  features: Record<string, boolean>;
  loaded: boolean;
  fetching: boolean;
  fetchEdition: () => Promise<void>;
}

export const useEditionStore = create<CommunityEditionState>((set) => ({
  edition: 'ce',
  mode: 'ce',
  productEdition: PRODUCT_EDITION,
  features: { ...SAFEHARNESS_CAPABILITIES, security_operations: false },
  loaded: true,
  fetching: false,
  fetchEdition: async () => {
    set({ fetching: true });
    const discovery = await discoverSafeHarnessCapabilities();
    if (discovery.available) {
      set({ features: discovery.capabilities });
    }
    set({ loaded: true, fetching: false });
  },
}));
