export type Language = 'tr' | 'en';
export type Span = { start: number; end: number };
export type Risk = 'none' | 'uncertain' | 'elevated' | 'high';

export type Signal =
  | 'urgency' | 'secrets' | 'payment' | 'reward' | 'impersonation'
  | 'mismatch' | 'ip' | 'punycode' | 'userinfo' | 'subdomain'
  | 'shortener' | 'lookalike' | 'unparsed';

export type Finding = {
  signal: Signal;
  span: Span;
  contextual: boolean;
};

export type InspectedLink = {
  raw: string;
  span: Span;
  signals: Signal[];
};

export type Unavailable = 'text' | 'links' | 'linkAccess' | 'ai' | 'fact' | 'source';

export type Analysis = {
  timestamp: string;
  method: typeof METHOD;
  risk: Risk;
  findings: Finding[];
  links: InspectedLink[];
  unavailable: Unavailable[];
};

export const METHOD = { id: 'local-phishing-rules', version: '1.0.0' } as const;

export type ProviderAssessment = {
  kind: 'ai-origin' | 'provenance' | 'fact-check';
  supportedLanguages: readonly string[];
  supportedMedia: readonly ('text' | 'image' | 'audio' | 'video')[];
  status: 'completed' | 'unsupported' | 'insufficient-evidence' | 'error';
  method: { id: string; version: string };
  findings: readonly string[];
  limitations: readonly string[];
  score?: { value: number; meaning: string };
};
