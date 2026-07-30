// Jest Setup — Global test initialization and utilities

beforeAll(() => {
  process.env.NODE_ENV = 'test';
});

afterEach(() => {
  jest.clearAllMocks();
});

// Global test utilities
(global as any).createMockReport = (overrides?: any) => ({
  id: 'test-report-1',
  title: 'Test Report',
  description: 'Test description',
  confidence: {
    sourceReliability: { score: 85, basis: 'Test source', weight: 0.25 },
    observationQuality: { score: 80, basis: 'Test observation', weight: 0.25 },
    technicalValidation: { score: 90, basis: 'Test validation', weight: 0.2 },
    analystVerification: { score: 75, basis: 'Test analyst', weight: 0.15 },
    independentCorroboration: { score: 70, basis: 'Test corroboration', weight: 0.15 },
    overallConfidence: 81,
    reasoning: 'High confidence based on testing',
    timestamp: new Date(),
    calculatedBy: 'test-system',
  },
  status: 'draft',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

(global as any).createMockIOC = (overrides?: any) => ({
  id: 'test-ioc-1',
  type: 'ipv4',
  value: '192.0.2.1',
  classification: 'malicious',
  confidence: 85,
  sources: ['test-source'],
  timestamp: new Date(),
  ...overrides,
});

(global as any).createMockWorkflowState = (overrides?: any) => ({
  reportId: 'test-report-1',
  state: 'draft',
  submittedBy: 'analyst-1',
  submittedAt: new Date(),
  reviewedBy: null,
  reviewedAt: null,
  approvedBy: null,
  approvedAt: null,
  status: 'pending',
  ...overrides,
});

// Suppress console output during tests unless explicitly needed
const originalError = console.error;
const originalLog = console.log;

beforeAll(() => {
  console.error = jest.fn((...args: any[]) => {
    if (
      typeof args[0] === 'string' &&
      (args[0].includes('React') || args[0].includes('warning'))
    ) {
      return;
    }
    originalError.call(console, ...args);
  });
});

afterAll(() => {
  console.error = originalError;
  console.log = originalLog;
});
