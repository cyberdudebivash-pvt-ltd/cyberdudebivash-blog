'use strict';

const crypto = require('crypto');

const CASE_STATUS = {
  OPEN: 'open',
  EVIDENCE_COLLECTION: 'evidence_collection',
  ANALYSIS: 'analysis',
  DECISION: 'decision',
  CLOSURE: 'closure',
  CLOSED: 'closed',
};

class CaseManager {
  constructor(redis, investigationManager) {
    this.redis = redis;
    this.investigationManager = investigationManager;
  }

  async createCase(investigationId, title, description) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const caseId = crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();

    const caseObj = {
      id: caseId,
      investigationId,
      title,
      description,
      status: CASE_STATUS.OPEN,
      createdAt: now,
      createdBy: 'analyst',
      updatedAt: now,
      evidenceCount: 0,
      noteCount: 0,
      taskCount: 0,
      version: 1,
    };

    const caseKey = `case:${caseId}`;
    await this.redis.hset(caseKey, Object.entries(caseObj).flat());
    await this.redis.expire(caseKey, 31536000);

    // Index case
    await this.redis.zadd(`investigation:cases:${investigationId}`, Date.now(), caseId);
    await this.redis.zadd('cases:all', Date.now(), caseId);
    await this.redis.zadd(`cases:by:status:${CASE_STATUS.OPEN}`, Date.now(), caseId);

    // Increment case count in investigation
    await this.redis.hincrby(`investigation:${investigationId}`, 'caseCount', 1);

    return caseObj;
  }

  async getCase(caseId) {
    const caseKey = `case:${caseId}`;
    const data = await this.redis.hgetall(caseKey);

    if (!data || data.length === 0) {
      return null;
    }

    const caseObj = {};
    for (let i = 0; i < data.length; i += 2) {
      caseObj[data[i]] = data[i + 1];
    }

    caseObj.evidenceCount = parseInt(caseObj.evidenceCount || 0);
    caseObj.noteCount = parseInt(caseObj.noteCount || 0);
    caseObj.taskCount = parseInt(caseObj.taskCount || 0);
    caseObj.version = parseInt(caseObj.version);

    return caseObj;
  }

  async updateCaseStatus(caseId, newStatus) {
    const caseObj = await this.getCase(caseId);
    if (!caseObj) throw new Error(`Case not found: ${caseId}`);

    const caseKey = `case:${caseId}`;
    const now = new Date().toISOString();

    // Update status
    await this.redis.hset(caseKey, 'status', newStatus);
    await this.redis.hset(caseKey, 'updatedAt', now);

    // Update indices
    await this.redis.zrem(`cases:by:status:${caseObj.status}`, caseId);
    await this.redis.zadd(`cases:by:status:${newStatus}`, Date.now(), caseId);

    return { caseId, status: newStatus };
  }

  async addNote(caseId, content, author) {
    const caseObj = await this.getCase(caseId);
    if (!caseObj) throw new Error(`Case not found: ${caseId}`);

    const noteId = crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();

    const note = {
      id: noteId,
      caseId,
      content,
      author,
      createdAt: now,
      updatedAt: now,
      version: 1,
    };

    const noteKey = `case:note:${noteId}`;
    await this.redis.hset(noteKey, Object.entries(note).flat());
    await this.redis.expire(noteKey, 31536000);

    // Index note
    await this.redis.zadd(`case:notes:${caseId}`, Date.now(), noteId);
    await this.redis.hincrby(`case:${caseId}`, 'noteCount', 1);

    return note;
  }

  async getNotes(caseId, limit = 50) {
    const noteIds = await this.redis.zrevrange(`case:notes:${caseId}`, 0, limit - 1);
    const notes = [];

    for (const noteId of noteIds) {
      const noteKey = `case:note:${noteId}`;
      const data = await this.redis.hgetall(noteKey);

      if (data && data.length > 0) {
        const note = {};
        for (let i = 0; i < data.length; i += 2) {
          note[data[i]] = data[i + 1];
        }
        notes.push(note);
      }
    }

    return notes;
  }

  async addTask(caseId, description, assignee, dueDate) {
    const caseObj = await this.getCase(caseId);
    if (!caseObj) throw new Error(`Case not found: ${caseId}`);

    const taskId = crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();

    const task = {
      id: taskId,
      caseId,
      description,
      assignee,
      dueDate,
      status: 'open',
      createdAt: now,
      completedAt: null,
    };

    const taskKey = `case:task:${taskId}`;
    await this.redis.hset(taskKey, Object.entries(task).flat());
    await this.redis.expire(taskKey, 31536000);

    // Index task
    await this.redis.zadd(`case:tasks:${caseId}`, Date.now(), taskId);
    await this.redis.hincrby(`case:${caseId}`, 'taskCount', 1);

    return task;
  }

  async completeTask(taskId) {
    const taskKey = `case:task:${taskId}`;
    const data = await this.redis.hgetall(taskKey);

    if (!data || data.length === 0) {
      throw new Error(`Task not found: ${taskId}`);
    }

    const now = new Date().toISOString();
    await this.redis.hset(taskKey, 'status', 'completed');
    await this.redis.hset(taskKey, 'completedAt', now);

    return { taskId, completed: true };
  }

  async getCaseInvestigation(caseId) {
    const caseObj = await this.getCase(caseId);
    if (!caseObj) return null;

    return await this.investigationManager.getInvestigation(caseObj.investigationId);
  }

  async addDecision(caseId, decision, justification, author) {
    const caseKey = `case:${caseId}`;
    const now = new Date().toISOString();

    const decisionRecord = {
      decision,
      justification,
      author,
      timestamp: now,
    };

    await this.redis.hset(caseKey, 'decision', JSON.stringify(decisionRecord));
    await this.redis.hset(caseKey, 'decisionAt', now);

    return decisionRecord;
  }

  async addRecommendation(caseId, recommendation, rationale) {
    const caseObj = await this.getCase(caseId);
    if (!caseObj) throw new Error(`Case not found: ${caseId}`);

    let recommendations = [];
    if (caseObj.recommendations) {
      try {
        recommendations = JSON.parse(caseObj.recommendations);
      } catch {
        recommendations = [];
      }
    }

    recommendations.push({
      id: crypto.randomBytes(8).toString('hex'),
      recommendation,
      rationale,
      timestamp: new Date().toISOString(),
    });

    const caseKey = `case:${caseId}`;
    await this.redis.hset(caseKey, 'recommendations', JSON.stringify(recommendations));

    return recommendations;
  }

  async closeCase(caseId, closureReason) {
    const caseObj = await this.getCase(caseId);
    if (!caseObj) throw new Error(`Case not found: ${caseId}`);

    const caseKey = `case:${caseId}`;
    const now = new Date().toISOString();

    await this.redis.hset(caseKey, 'status', CASE_STATUS.CLOSED);
    await this.redis.hset(caseKey, 'closedAt', now);
    await this.redis.hset(caseKey, 'closureReason', closureReason);

    // Update status indices
    await this.redis.zrem(`cases:by:status:${caseObj.status}`, caseId);
    await this.redis.zadd(`cases:by:status:${CASE_STATUS.CLOSED}`, Date.now(), caseId);

    return { caseId, closed: true };
  }

  async getCaseSummary(caseId) {
    const caseObj = await this.getCase(caseId);
    if (!caseObj) throw new Error(`Case not found: ${caseId}`);

    const notes = await this.getNotes(caseId, 100);

    return {
      case: caseObj,
      notes,
      noteCount: notes.length,
    };
  }
}

module.exports = {
  CaseManager,
  CASE_STATUS,
};
