'use strict';

class EditorialCalendarEngine {
  constructor() {
    this.calendar = new Map();
    this.events = [];
  }

  planIntelligenceCalendar(quarter, year) {
    const calendarPlan = {
      quarter,
      year,
      plannedPublications: [],
      plannedUpdates: [],
      plannedRetirements: [],
      targetMetrics: {
        dailyIntelligence: 2,
        weeklyReports: 4,
        monthlyReports: 2,
        campaignTracking: 10,
        threatActorMonitoring: 15,
        industryReports: 2,
        executiveBriefings: 4,
        flashAlerts: 10,
        vulnerabilityAdvisories: 20,
      },
      calendar: this.generateQuarterlyCalendar(quarter, year),
      createdAt: new Date().toISOString(),
    };

    return calendarPlan;
  }

  generateQuarterlyCalendar(quarter, year) {
    const monthsByQuarter = {
      1: [1, 2, 3],
      2: [4, 5, 6],
      3: [7, 8, 9],
      4: [10, 11, 12],
    };

    const months = monthsByQuarter[quarter] || [];
    const calendar = [];

    months.forEach(month => {
      const daysInMonth = new Date(year, month, 0).getDate();

      for (let day = 1; day <= daysInMonth; day++) {
        const date = new Date(year, month - 1, day);
        const dayOfWeek = date.getDay();
        const weekNum = Math.ceil(day / 7);

        calendar.push({
          date: date.toISOString().split('T')[0],
          dayOfWeek,
          week: weekNum,
          plannedPublications: [],
          plannedUpdates: [],
          capacity: 'normal',
        });
      }
    });

    return calendar;
  }

  scheduleIntelligenceDrop(publication) {
    const event = {
      id: publication.id,
      type: publication.type || 'report',
      title: publication.title,
      scheduledDate: publication.scheduledDate || new Date().toISOString(),
      priority: publication.priority || 'normal',
      leadAnalyst: publication.leadAnalyst,
      estimatedReviewHours: publication.estimatedReviewHours || 8,
      dependencies: publication.dependencies || [],
      status: 'scheduled',
      createdAt: new Date().toISOString(),
    };

    this.events.push(event);
    return event;
  }

  getCalendarView(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    return {
      period: { start: startDate, end: endDate },
      events: this.events.filter(e => {
        const eventDate = new Date(e.scheduledDate);
        return eventDate >= start && eventDate <= end;
      }).sort((a, b) => new Date(a.scheduledDate) - new Date(b.scheduledDate)),
      workloadDistribution: this.calculateWorkloadDistribution(start, end),
      capacityWarnings: this.identifyCapacityIssues(start, end),
    };
  }

  calculateWorkloadDistribution(start, end) {
    const distribution = {};
    const current = new Date(start);

    while (current <= end) {
      const dateStr = current.toISOString().split('T')[0];
      const dayEvents = this.events.filter(e => e.scheduledDate.startsWith(dateStr));
      const totalHours = dayEvents.reduce((sum, e) => sum + (e.estimatedReviewHours || 8), 0);

      distribution[dateStr] = {
        eventCount: dayEvents.length,
        estimatedHours: totalHours,
        capacity: totalHours > 8 ? 'overloaded' : totalHours > 6 ? 'high' : 'normal',
      };

      current.setDate(current.getDate() + 1);
    }

    return distribution;
  }

  identifyCapacityIssues(start, end) {
    const warnings = [];
    const distribution = this.calculateWorkloadDistribution(start, end);

    Object.entries(distribution).forEach(([date, data]) => {
      if (data.capacity === 'overloaded') {
        warnings.push({
          date,
          issue: 'Overloaded capacity',
          events: data.eventCount,
          hours: data.estimatedHours,
          recommendation: 'Reschedule low-priority items',
        });
      }
    });

    return warnings;
  }

  planCampaignTracking(campaign) {
    return {
      campaign: campaign.id,
      monitoringPeriod: 90,
      updateFrequency: 'weekly',
      plannedUpdates: this.generateUpdateSchedule(campaign, 90, 'weekly'),
      assignedAnalyst: campaign.assignedAnalyst,
      status: 'planned',
    };
  }

  planThreatActorMonitoring(actor) {
    return {
      actor: actor.id,
      monitoringPeriod: 180,
      updateFrequency: 'bi-weekly',
      plannedUpdates: this.generateUpdateSchedule(actor, 180, 'bi-weekly'),
      assignedAnalyst: actor.assignedAnalyst,
      status: 'planned',
    };
  }

  generateUpdateSchedule(entity, days, frequency) {
    const schedule = [];
    const interval = frequency === 'daily' ? 1 : frequency === 'weekly' ? 7 : frequency === 'bi-weekly' ? 14 : 30;

    for (let i = 0; i < days; i += interval) {
      const date = new Date();
      date.setDate(date.getDate() + i);

      schedule.push({
        date: date.toISOString().split('T')[0],
        type: 'monitoring_update',
        priority: this.assessPriority(entity, i),
      });
    }

    return schedule;
  }

  assessPriority(entity, daysOut) {
    if (daysOut === 0) return 'critical';
    if (daysOut <= 7) return 'high';
    if (daysOut <= 30) return 'medium';
    return 'low';
  }

  getAnalystWorkload(analystId, daysAhead = 30) {
    const start = new Date();
    const end = new Date();
    end.setDate(end.getDate() + daysAhead);

    const assignments = this.events.filter(e =>
      e.leadAnalyst === analystId && new Date(e.scheduledDate) <= end && new Date(e.scheduledDate) >= start
    );

    const totalHours = assignments.reduce((sum, a) => sum + (a.estimatedReviewHours || 8), 0);
    const avgHoursPerDay = totalHours / daysAhead;

    return {
      analyst: analystId,
      period: { start: start.toISOString(), end: end.toISOString() },
      assignments: assignments.length,
      totalHours,
      avgHoursPerDay,
      capacity: avgHoursPerDay > 8 ? 'overloaded' : avgHoursPerDay > 6 ? 'high' : 'normal',
    };
  }

  suggestPublicationDate(publication, consideredFactors = {}) {
    const now = new Date();
    const suggestedDate = new Date(now);

    const minDaysOut = consideredFactors.minDaysOut || 1;
    suggestedDate.setDate(suggestedDate.getDate() + minDaysOut);

    const workload = this.getAnalystWorkload(publication.leadAnalyst, 30);
    if (workload.capacity === 'overloaded') {
      suggestedDate.setDate(suggestedDate.getDate() + 7);
    }

    const dayOfWeek = suggestedDate.getDay();
    if (dayOfWeek === 0) suggestedDate.setDate(suggestedDate.getDate() + 1);
    if (dayOfWeek === 6) suggestedDate.setDate(suggestedDate.getDate() + 2);

    return {
      suggestedDate: suggestedDate.toISOString().split('T')[0],
      reasoning: [
        `Minimum lead time: ${minDaysOut} days`,
        `Lead analyst workload: ${workload.capacity}`,
        `Avoiding weekend: ${dayOfWeek === 0 || dayOfWeek === 6}`,
      ],
    };
  }
}

module.exports = { EditorialCalendarEngine };
