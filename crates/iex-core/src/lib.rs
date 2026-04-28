pub mod engine;
pub mod expr;
pub mod inspect;
pub mod stats;

pub use engine::{
    prepare_search_targets, run_search, run_search_prepared, PreparedSearchOptions,
    PreparedSearchTargets, SearchConfig, SearchHit, SearchReport,
};
pub use expr::{ExpressionPlan, LogicMode, PredicateDescriptor};
pub use inspect::{
    inspect_window, InspectLine, InspectWindowBounds, InspectWindowReport, InspectWindowRequest,
};
pub use stats::{
    ConcurrencyStats, PhaseTimings, RegexDecompositionStats, SearchStats, SlowFileStat,
    UnicodeCaseFoldPrefilterStats,
};
