import javascript
// import semmle.javascript.security.dataflow.Xss
import semmle.javascript.frameworks.AngularJS.ServiceDefinitions
import semmle.javascript.frameworks.AngularJS.AngularJSCore

from Variable sce, DataFlow::SourceNode step1
where 
sce.getName() = "$sce" 
and
sce.getAReference() = step1.asExpr()
select step1.getAMethodCall().getAnArgument()
