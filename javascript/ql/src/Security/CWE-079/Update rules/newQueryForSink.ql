import javascript

from TaggedTemplateExpr expr, DataFlow::CallNode call
where 
call = DataFlow::moduleImport("styled-components").getACall() 
// and 
// expr.getTag() = call.getReceiver().asExpr()
select call.getEnclosingExpr()