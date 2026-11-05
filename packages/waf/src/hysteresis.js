                                   
                              
                                 
 

                                      
           
                      
 

                                      
                           
                      
                          
                            
 

/**
 * Deterministic Hysteresis Engine to eliminate false transitions caused by edge CDN cache invalidation races.
 */
export class HysteresisTracker    {
          effectiveValue   ;
          pendingCandidate           = null;
          streak = 0;
                   config                  ;

  constructor(initialValue   , config                            = {}) {
    this.effectiveValue = initialValue;
    this.config = {
      restockConfirmTicks: config.restockConfirmTicks ?? 2,
      outOfStockConfirmTicks: config.outOfStockConfirmTicks ?? 2,
    };
  }

         observe(observedValue   )                      {
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

         getEffective()    {
    return this.effectiveValue;
  }
}
