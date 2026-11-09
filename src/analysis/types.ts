export type Language = 'tr' | 'en';
export type Span = { start: number; end: number };
export type Risk = 'none' | 'uncertain' | 'elevated' | 'high';

export type Signal =
  | 'urgency' | 'secrets' | 'payment' | 'reward' | 'impersonation'
  | 'delivery' | 'invoice' | 'login' | 'approval' | 'remoteAccess'
  | 'attachment' | 'callback' | 'qr' | 'replyMismatch'
  | 'mismatch' | 'ip' | 'punycode' | 'userinfo' | 'subdomain'
  | 'shortener' | 'lookalike' | 'unparsed' | 'redirect' | 'download' | 'defanged';

export type RiskReason =
  | 'requestAndDeception' | 'requestAndPressure' | 'actionAndDeception'
  | 'sensitiveRequest' | 'destinationDeception' | 'pressureAndPretext'
  | 'actionAndPretext' | 'limitedEvidence' | 'noIndicators';

export type Finding = {
  signal: Signal;
  span: Span;
  contextual: boolean;
};

export type InspectedLink = {
  raw: string;
  span: Span;
  signals: Signal[];
  hostname?: string;
  domain?: string;
};

export type Unavailable = 'text' | 'links' | 'senderHeaders' | 'senderAuthentication' | 'linkAccess';

export type Analysis = {
  timestamp: string;
  method: typeof METHOD;
  risk: Risk;
  reason: RiskReason;
  findings: Finding[];
  links: InspectedLink[];
  unavailable: Unavailable[];
};

export const METHOD = { id: 'local-phishing-rules', version: '2.0.0' } as const;
