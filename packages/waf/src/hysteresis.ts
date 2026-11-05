export interface HysteresisConfig {
  restockConfirmTicks: number;
  outOfStockConfirmTicks: number;
}

export interface StateObservation<T> {
  value: T;
  timestampMs: number;
}

export interface HysteresisResult<T> {
  currentEffectiveValue: T;
  rawObservedValue: T;
  confirmedStreak: number;
  isFlapSuppressed: boolean;
}

/**
 * Deterministic Hysteresis Engine to eliminate false transitions caused by edge CDN cache invalidation races.
 */
export class HysteresisTracker<T> {
  private effectiveValue: T;
  private pendingCandidate: T | null = null;
  private streak = 0;
  private readonly config: HysteresisConfig;

  constructor(initialValue: T, config: Partial<HysteresisConfig> = {}) {
    this.effectiveValue = initialValue;
    this.config = {
      restockConfirmTicks: config.restockConfirmTicks ?? 2,
      outOfStockConfirmTicks: config.outOfStockConfirmTicks ?? 2,
    };
  }

  public observe(observedValue: T): HysteresisResult<T> {
    if (observedValue === this.effectiveValue) {
      this.pendingCandidate = null;
      this.streak = 0;
      return {
        currentEffectiveValue: this.effectiveValue,
        rawObservedValue: observedValue,
        confirmedStreak: 0,
        isFlapSuppressed: false,
      };
    }

    if (this.pendingCandidate === observedValue) {
      this.streak++;
    } else {
      this.pendingCandidate = observedValue;
      this.streak = 1;
    }

    const requiredTicks = observedValue ? this.config.restockConfirmTicks : this.config.outOfStockConfirmTicks;

    if (this.streak >= requiredTicks) {
      this.effectiveValue = observedValue;
      this.pendingCandidate = null;
      return {
        currentEffectiveValue: this.effectiveValue,
        rawObservedValue: observedValue,
        confirmedStreak: this.streak,
        isFlapSuppressed: false,
      };
    }

    return {
      currentEffectiveValue: this.effectiveValue,
      rawObservedValue: observedValue,
      confirmedStreak: this.streak,
      isFlapSuppressed: true,
    };
  }

  public getEffective(): T {
    return this.effectiveValue;
  }
}
