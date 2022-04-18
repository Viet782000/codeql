import javascript
import semmle.javascript.security.dataflow.Xss
import semmle.javascript.frameworks.AngularJS.ServiceDefinitions
import semmle.javascript.frameworks.AngularJS.AngularJSCore

from  Variable sce, DataFlow::SourceNode step1, DataFlow::FunctionNode step2, DataFlow::SourceNode scopeSource
where 
sce.getName() = "$sce" 
and
sce.getAReference() = step1.asExpr()
and
step1.getAMethodCall().getAnArgument() = step2
and
step2.getName() = "$scope"
and 
step2 = scopeSource
select scopeSource