interface ImportMetaEnv {
  readonly VITE_PORT?: string;
  readonly VITE_PROXY_TARGET?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
