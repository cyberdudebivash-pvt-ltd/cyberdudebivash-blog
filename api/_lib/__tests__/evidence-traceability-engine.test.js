'use strict';

const { EvidenceTraceabilityEngine } = require('../evidence-traceability-engine');

describe('EvidenceTraceabilityEngine — traceStatement source shape', () => {
  const engine = new EvidenceTraceabilityEngine();

  // A statement that matches every source type below via matchesStatement()'s
  // keyword-overlap check (>=2 of the statement's first 5 words present in
  // JSON.stringify(source)).
  const statement = { text: 'suspicious lateral movement observed hostname', path: 'x' };

  test('IOC source keeps entity discriminator "ioc" in `type` and the IOC kind in `subtype`', () => {
    const investigation = {
      iocs: [
        { id: 'ioc-1', value: 'suspicious-lateral-movement.example', ioType: 'domain', firstSeen: '2026-01-01', lastSeen: '2026-01-02' },
      ],
    };

    const { sources } = engine.traceStatement(statement, investigation, {});

    expect(sources).toHaveLength(1);
    // Regression guard: a duplicate `type` key in the object literal used to
    // let `ioc.ioType` silently overwrite the 'ioc' entity-type discriminator
    // (JS object literals keep only the last value for a repeated key).
    expect(sources[0].type).toBe('ioc');
    expect(sources[0].subtype).toBe('domain');
    expect(sources[0].id).toBe('ioc-1');
  });

  test('infrastructure source keeps entity discriminator "infrastructure" in `type` and the infra kind in `subtype`', () => {
    const investigation = {
      infrastructure: [
        { id: 'infra-1', ip: '203.0.113.5', type: 'c2-server' },
      ],
    };

    const statementForInfra = { text: 'lateral movement c2-server 203 0 113', path: 'x' };
    const { sources } = engine.traceStatement(statementForInfra, investigation, {});

    expect(sources).toHaveLength(1);
    expect(sources[0].type).toBe('infrastructure');
    expect(sources[0].subtype).toBe('c2-server');
    expect(sources[0].address).toBe('203.0.113.5');
  });

  test('sourceTypeDistribution groups real traceStatement() output by the entity-type discriminator', () => {
    // Real traceStatement() output for one IOC source and one infrastructure
    // source (each independently verified above), fed into
    // calculateTraceabilityMetrics() to isolate its grouping-by-`type`
    // behavior. Before the fix, both sources' `type` fields were clobbered
    // by their subtype value, so this would NOT have grouped as 'ioc'/
    // 'infrastructure'.
    const iocTrace = engine.traceStatement(
      statement,
      { iocs: [{ id: 'ioc-1', value: 'suspicious lateral movement hostname', ioType: 'domain' }] },
      {}
    );
    const infraTrace = engine.traceStatement(
      statement,
      { infrastructure: [{ id: 'infra-1', domain: 'suspicious lateral movement hostname', type: 'c2-server' }] },
      {}
    );

    const metrics = engine.calculateTraceabilityMetrics([{ trace: iocTrace }, { trace: infraTrace }]);

    expect(metrics.sourceTypeDistribution).toEqual({ ioc: 1, infrastructure: 1 });
  });
});
