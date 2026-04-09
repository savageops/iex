pub mod engine;
pub mod expr;
pub mod stats;

pub use engine::{run_search, SearchConfig, SearchHit, SearchReport};
pub use expr::{ExpressionPlan, LogicMode, PredicateDescriptor};
pub use stats::{PhaseTimings, SearchStats, SlowFileStat};
