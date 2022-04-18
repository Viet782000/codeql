// import javascript

// from DataFlow::Node create, string name
// where create = DataFlow::globalVarRef("location").getAPropertyReference(name)
// select create, name

/**
* @name Cross-site scripting vulnerable plugin
* @kind path-problem
* @id js/xss-unsafe-plugin
*/

import javascript
import DataFlow::PathGraph

class XssUnsafeMethod extends TaintTracking::Configuration {
  XssUnsafeMethod() { this = "XssUnsafeMethod" }

  override predicate isSource(DataFlow::Node source) {
    // exists(DataFlow::FunctionNode call |
    //   source = call.getLastParameter()
    //   )
      source instanceof ClientRequest
  }

  override predicate isSink(DataFlow::Node sink) {
      sink = DataFlow::globalVarRef("location").getAMethodCall().getArgument(0)
  }
}

from XssUnsafeMethod cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Potential XSS vulnerability in location method."