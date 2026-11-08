/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_RPC_URL: string;
  /** Swarm roster: addresses shown in the r0 form (display only; #309). */
  readonly VITE_SWARM_ROSTER?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
