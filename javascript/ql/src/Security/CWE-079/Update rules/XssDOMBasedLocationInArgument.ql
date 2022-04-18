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
import semmle.javascript.security.dataflow.ConditionalBypassCustomizations
import DataFlow::PathGraph

class XssDOMBasedUpdate extends TaintTracking::Configuration {
    XssDOMBasedUpdate() { this = "XssDOMBasedUpdate" }

  override predicate isSource(DataFlow::Node source) {
    // exists(DataFlow::MethodCallNode call, string name | 
    //         call = DataFlow::globalVarRef("document").getAMethodCall(name) 
    //         and source = call.getAnArgument()
    //   )
       exists(DataFlow::MethodCallNode call | 
        call.getReceiver() instanceof ConditionalBypass::RemoteFlowSourceAsSource
        and call instanceof StringOps::HtmlConcatenationNode
        and source = call
      )
      // source = DataFlow::globalVarRef("location").getAPropertyRead()
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call, string name |
        call = DataFlow::globalVarRef("document").getAMethodCall(name)
        and sink = call.getAnArgument()
      )
  }

//   override predicate isSanitizer(DataFlow::Node sanitizer) {
//     exists(DataFlow::MethodCallNode call, DataFlow::SourceNode sourcecode |
//       DOM::documentRef().getAMethodCall() = call
//       and call.getAnArgument() = sourcecode and
//       sanitizer = sourcecode
//     )
// }

}


from XssDOMBasedUpdate cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Potential XSS DomBase vulnerability in argument."

