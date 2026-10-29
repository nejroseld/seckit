export type FormView = {
  phase: 'idle' | 'entry' | 'done'
  name: string
  kind: 'token' | 'login'
  service: string
  lengths: number[]
  message: string
  outcome: 'none' | 'stored' | 'cancelled' | 'failed' | 'expired'
}

declare module 'claude-code' {
  interface PluginState {
    'guardkit-input': { view: Shaped<FormView> }
  }
}
