export interface PluginInfo {
  name: string;
  category: 'process' | 'network' | 'malware' | 'system' | 'misc';
}

export type LoadingState = 'idle' | 'loading' | 'success' | 'error';
