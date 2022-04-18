import javascript
import semmle.javascript.security.dataflow.Xss

class ReactDangerousSetInnerHTMLSinks extends Shared::Sink {
  ReactDangerousSetInnerHTMLSinks() {
    exists(JSXAttribute attr |
      attr.getName() = "dangerouslySetInnerHTML" and attr.getValue() = this.asExpr()
    )
  }
}

class ReactStyledComponents extends Shared::Sink {
  ReactStyledComponents() {
    // exists(DataFlow::CallNode call |
    //   call = DataFlow::moduleImport("styled-components").getACall()
    //   and
    //   call.getCallback(0).getReturnNode() = this
    //   // call.getALocalSource() = this
    // )
    // or
    exists(TaggedTemplateExpr expr, DataFlow::CallNode call |
      call = DataFlow::moduleImport("styled-components").getACall()
      and
      // call.flowsTo(expr.getTag().flow()) = this
      // and 
      call.getAMethodCall().asExpr() = expr.getTag() 
      and
      call = this
    )
  }
}
