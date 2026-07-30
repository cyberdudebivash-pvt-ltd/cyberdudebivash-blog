// Database Helpers — Test database initialization and cleanup

export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
}

export class DatabaseTestHelper {
  private config: DatabaseConfig;
  private connection: any = null;

  constructor(config?: Partial<DatabaseConfig>) {
    this.config = {
      host: config?.host || 'localhost',
      port: config?.port || 5432,
      database: config?.database || 'test_sentinel_apex',
      user: config?.user || 'test_user',
      password: config?.password || 'test_password',
    };
  }

  async connect(): Promise<void> {
    // Mock connection for testing
    this.connection = {
      connected: true,
      query: async (sql: string) => ({ rows: [] }),
      end: async () => {},
    };
  }

  async disconnect(): Promise<void> {
    if (this.connection) {
      await this.connection.end();
      this.connection = null;
    }
  }

  async dropTestDatabase(): Promise<void> {
    if (!this.connection) return;
    await this.connection.query(`DROP DATABASE IF EXISTS ${this.config.database} CASCADE;`);
  }

  async createTestDatabase(): Promise<void> {
    if (!this.connection) return;
    await this.connection.query(`CREATE DATABASE ${this.config.database};`);
  }

  async resetDatabase(): Promise<void> {
    await this.dropTestDatabase();
    await this.createTestDatabase();
  }

  async initializeSchema(): Promise<void> {
    if (!this.connection) return;

    // Reports table
    await this.connection.query(`
      CREATE TABLE IF NOT EXISTS reports (
        id UUID PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        status VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // IOCs table
    await this.connection.query(`
      CREATE TABLE IF NOT EXISTS iocs (
        id UUID PRIMARY KEY,
        type VARCHAR(50) NOT NULL,
        value VARCHAR(1024) NOT NULL,
        classification VARCHAR(50),
        confidence INTEGER,
        source VARCHAR(255),
        report_id UUID REFERENCES reports(id),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(type, value)
      );
    `);

    // Governance workflows table
    await this.connection.query(`
      CREATE TABLE IF NOT EXISTS workflows (
        id UUID PRIMARY KEY,
        report_id UUID REFERENCES reports(id),
        state VARCHAR(50) NOT NULL,
        submitted_by VARCHAR(255),
        submitted_at TIMESTAMP,
        reviewed_by VARCHAR(255),
        reviewed_at TIMESTAMP,
        approved_by VARCHAR(255),
        approved_at TIMESTAMP,
        status VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Audit trail table
    await this.connection.query(`
      CREATE TABLE IF NOT EXISTS audit_trail (
        id UUID PRIMARY KEY,
        entity_type VARCHAR(50),
        entity_id UUID,
        action VARCHAR(50),
        actor VARCHAR(255),
        changes JSONB,
        timestamp TIMESTAMP DEFAULT NOW()
      );
    `);

    // Detection rules table
    await this.connection.query(`
      CREATE TABLE IF NOT EXISTS detection_rules (
        id UUID PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        format VARCHAR(50),
        content TEXT NOT NULL,
        confidence INTEGER,
        enabled BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
  }

  async seedTestData(): Promise<void> {
    if (!this.connection) return;

    // Insert sample reports
    await this.connection.query(`
      INSERT INTO reports (id, title, description, status)
      VALUES
        ('550e8400-e29b-41d4-a716-446655440000', 'Test Report 1', 'Test Description 1', 'draft'),
        ('550e8400-e29b-41d4-a716-446655440001', 'Test Report 2', 'Test Description 2', 'published')
      ON CONFLICT DO NOTHING;
    `);

    // Insert sample IOCs
    await this.connection.query(`
      INSERT INTO iocs (id, type, value, classification, confidence, source)
      VALUES
        ('650e8400-e29b-41d4-a716-446655440000', 'ipv4', '192.0.2.1', 'malicious', 85, 'test-source'),
        ('650e8400-e29b-41d4-a716-446655440001', 'domain', 'malware.test', 'malicious', 90, 'test-source')
      ON CONFLICT DO NOTHING;
    `);
  }

  async clearAllTables(): Promise<void> {
    if (!this.connection) return;

    const tables = ['audit_trail', 'workflows', 'iocs', 'detection_rules', 'reports'];
    for (const table of tables) {
      await this.connection.query(`TRUNCATE TABLE ${table} CASCADE;`);
    }
  }

  async getRowCount(table: string): Promise<number> {
    if (!this.connection) return 0;
    const result = await this.connection.query(`SELECT COUNT(*) as count FROM ${table};`);
    return result.rows[0]?.count || 0;
  }

  async getAllRows(table: string): Promise<any[]> {
    if (!this.connection) return [];
    const result = await this.connection.query(`SELECT * FROM ${table};`);
    return result.rows || [];
  }

  isConnected(): boolean {
    return this.connection?.connected || false;
  }
}

export class DatabaseFixture {
  private helper: DatabaseTestHelper;

  constructor(config?: Partial<DatabaseConfig>) {
    this.helper = new DatabaseTestHelper(config);
  }

  async setup(): Promise<void> {
    await this.helper.connect();
    await this.helper.resetDatabase();
    await this.helper.initializeSchema();
    await this.helper.seedTestData();
  }

  async teardown(): Promise<void> {
    await this.helper.clearAllTables();
    await this.helper.disconnect();
  }

  getHelper(): DatabaseTestHelper {
    return this.helper;
  }
}

export const createDatabaseFixture = (
  config?: Partial<DatabaseConfig>
): DatabaseFixture => new DatabaseFixture(config);
