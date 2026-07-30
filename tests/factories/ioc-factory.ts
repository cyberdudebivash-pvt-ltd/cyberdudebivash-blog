// IOC Factory — Dynamic indicator test data generation

import { v4 as uuid } from 'uuid';

export interface IOCTestData {
  id: string;
  type: string;
  value: string;
  classification: string;
  confidence: number;
  sources: string[];
  timestamp: Date;
  metadata?: Record<string, any>;
}

export class IOCFactory {
  static createIPv4(overrides?: Partial<IOCTestData>): IOCTestData {
    return {
      id: uuid(),
      type: 'ipv4',
      value: '192.0.2.1',
      classification: 'malicious',
      confidence: 85,
      sources: ['test-source'],
      timestamp: new Date(),
      ...overrides,
    };
  }

  static createIPv6(overrides?: Partial<IOCTestData>): IOCTestData {
    return {
      id: uuid(),
      type: 'ipv6',
      value: '2001:db8::1',
      classification: 'suspicious',
      confidence: 65,
      sources: ['test-source'],
      timestamp: new Date(),
      ...overrides,
    };
  }

  static createDomain(overrides?: Partial<IOCTestData>): IOCTestData {
    return {
      id: uuid(),
      type: 'domain',
      value: 'malware.test',
      classification: 'malicious',
      confidence: 90,
      sources: ['test-source'],
      timestamp: new Date(),
      ...overrides,
    };
  }

  static createURL(overrides?: Partial<IOCTestData>): IOCTestData {
    return {
      id: uuid(),
      type: 'url',
      value: 'http://malware.test/payload.exe',
      classification: 'malicious',
      confidence: 88,
      sources: ['test-source'],
      timestamp: new Date(),
      ...overrides,
    };
  }

  static createHash(
    algorithm: 'md5' | 'sha1' | 'sha256' = 'sha256',
    overrides?: Partial<IOCTestData>
  ): IOCTestData {
    const hashes = {
      md5: 'd41d8cd98f00b204e9800998ecf8427e',
      sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    };

    return {
      id: uuid(),
      type: `hash_${algorithm}`,
      value: hashes[algorithm],
      classification: 'malicious',
      confidence: 92,
      sources: ['test-source'],
      timestamp: new Date(),
      ...overrides,
    };
  }

  static createEmail(overrides?: Partial<IOCTestData>): IOCTestData {
    return {
      id: uuid(),
      type: 'email',
      value: 'attacker@malware.test',
      classification: 'malicious',
      confidence: 75,
      sources: ['test-source'],
      timestamp: new Date(),
      ...overrides,
    };
  }

  static createUserAgent(overrides?: Partial<IOCTestData>): IOCTestData {
    return {
      id: uuid(),
      type: 'user_agent',
      value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
      classification: 'suspicious',
      confidence: 60,
      sources: ['test-source'],
      timestamp: new Date(),
      ...overrides,
    };
  }

  static createMutex(overrides?: Partial<IOCTestData>): IOCTestData {
    return {
      id: uuid(),
      type: 'mutex',
      value: 'Global\\MalwareMutex123',
      classification: 'malicious',
      confidence: 80,
      sources: ['test-source'],
      timestamp: new Date(),
      ...overrides,
    };
  }

  static createRandomType(overrides?: Partial<IOCTestData>): IOCTestData {
    const types = [
      () => this.createIPv4(),
      () => this.createIPv6(),
      () => this.createDomain(),
      () => this.createURL(),
      () => this.createHash('sha256'),
      () => this.createEmail(),
      () => this.createUserAgent(),
      () => this.createMutex(),
    ];

    const creator = types[Math.floor(Math.random() * types.length)];
    const ioc = creator();
    return { ...ioc, ...overrides };
  }

  static createCorpus(count: number, distribution?: Record<string, number>): IOCTestData[] {
    const defaultDistribution = {
      ipv4: Math.floor(count * 0.15),
      ipv6: Math.floor(count * 0.05),
      domain: Math.floor(count * 0.25),
      url: Math.floor(count * 0.2),
      hash_sha256: Math.floor(count * 0.15),
      email: Math.floor(count * 0.1),
      user_agent: Math.floor(count * 0.05),
      mutex: Math.floor(count * 0.05),
    };

    const finalDistribution = { ...defaultDistribution, ...distribution };
    const iocs: IOCTestData[] = [];

    if (finalDistribution.ipv4 > 0) {
      iocs.push(
        ...Array.from({ length: finalDistribution.ipv4 }, (_, i) =>
          this.createIPv4({
            id: uuid(),
            value: `192.0.2.${(i % 256) + 1}`,
          })
        )
      );
    }

    if (finalDistribution.ipv6 > 0) {
      iocs.push(
        ...Array.from({ length: finalDistribution.ipv6 }, (_, i) =>
          this.createIPv6({
            id: uuid(),
            value: `2001:db8::${i + 1}`,
          })
        )
      );
    }

    if (finalDistribution.domain > 0) {
      iocs.push(
        ...Array.from({ length: finalDistribution.domain }, (_, i) =>
          this.createDomain({
            id: uuid(),
            value: `domain${i}.test`,
          })
        )
      );
    }

    if (finalDistribution.url > 0) {
      iocs.push(
        ...Array.from({ length: finalDistribution.url }, (_, i) =>
          this.createURL({
            id: uuid(),
            value: `http://malware${i}.test/payload`,
          })
        )
      );
    }

    if (finalDistribution.hash_sha256 > 0) {
      iocs.push(
        ...Array.from({ length: finalDistribution.hash_sha256 }, (_, i) =>
          this.createHash('sha256', {
            id: uuid(),
            value: i.toString(16).padStart(64, '0'),
          })
        )
      );
    }

    if (finalDistribution.email > 0) {
      iocs.push(
        ...Array.from({ length: finalDistribution.email }, (_, i) =>
          this.createEmail({
            id: uuid(),
            value: `attacker${i}@malware.test`,
          })
        )
      );
    }

    if (finalDistribution.user_agent > 0) {
      iocs.push(
        ...Array.from({ length: finalDistribution.user_agent }, (_, i) =>
          this.createUserAgent({
            id: uuid(),
            value: `CustomUserAgent/${i}`,
          })
        )
      );
    }

    if (finalDistribution.mutex > 0) {
      iocs.push(
        ...Array.from({ length: finalDistribution.mutex }, (_, i) =>
          this.createMutex({
            id: uuid(),
            value: `Global\\Mutex${i}`,
          })
        )
      );
    }

    return iocs;
  }

  static createBatch(count: number): IOCTestData[] {
    return Array.from({ length: count }, () => this.createRandomType());
  }
}
