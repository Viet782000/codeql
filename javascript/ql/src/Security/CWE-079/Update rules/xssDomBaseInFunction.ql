// import javascript

// from DataFlow::Node create, string name
// where create = DataFlow::globalVarRef("location").getAPropertyReference(name)
// select create, name

/**
* @name Cross-site scripting vulnerable DOMBase
* @kind path-problem
* @id js/xss-DOMBase
*/

import javascript
import DataFlow::PathGraph

class XssDOMBaseTwo extends TaintTracking::Configuration {
    XssDOMBaseTwo() { this = "XssDOMBaseTwo" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode call |
      source = call.getAParameter()
      )
  }

  override predicate isSink(DataFlow::Node sink) {
      sink = DataFlow::globalVarRef("document").getAMethodCall().getAnArgument()
  }
}

from XssDOMBaseTwo cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Potential XSS DOMBase vulnerability"