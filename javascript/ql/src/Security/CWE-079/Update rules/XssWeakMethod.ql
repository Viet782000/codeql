/**
* @name Cross-site scripting vulnerable
* @kind path-problem
* @id js/xss-weak-method
*/

import javascript
import DataFlow::PathGraph
import semmle.javascript.frameworks.React
// import ReactUpdate

class XssWeakMethod extends TaintTracking::Configuration {
    XssWeakMethod() { this = "XssWeakMethod" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode call |
      source = call.getAParameter()
      )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::PropWrite pw|
        pw.getPropertyName().regexpMatch("(innerHTML|outerHTML)")
        and sink = pw.getRhs()
        )
    // sink instanceof ReactDangerousSetInnerHTMLSinks
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(TaggedTemplateExpr expr, DataFlow::CallNode call |
      call = DataFlow::moduleImport("styled-components").getACall() and
      pred = call.getArgument(0) and
      call.flowsTo(expr.getTag().flow()) and
      succ = expr.flow()
    )
 }
}

from XssWeakMethod cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Potential XSS Weak Method vulnerability"