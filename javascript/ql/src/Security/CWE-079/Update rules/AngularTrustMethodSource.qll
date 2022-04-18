import javascript
import semmle.javascript.security.dataflow.Xss
import semmle.javascript.frameworks.AngularJS.ServiceDefinitions
import semmle.javascript.frameworks.AngularJS.AngularJSCore

class AngularTrustMethodSource extends Shared::Source {
  AngularTrustMethodSource() {
    exists(
      ModuleApiCallDependencyInjection functionScope,
      DataFlow::FunctionNode scopeParameter, DataFlow::SourceNode scopeSource
    |
      functionScope.getAnInjectableFunction() = scopeParameter and
      scopeParameter.getAParameter().getName() = "$scope" and
      scopeParameter.getAParameter() = scopeSource 
      and scopeSource.getAPropertyReference() = this
    )
    or
    exists(
      DataFlow::CallNode call, Variable var, DataFlow::SourceNode step1,
      DataFlow::FunctionNode step2, DataFlow::SourceNode scopeSource
    |
      call = angular().getAMethodCall("module") and
      call.getALocalUse().asExpr() = var.getAnAssignedExpr() and
      var.getAnAccess() = step1.asExpr() and
      step1.getAMethodCall().getAnArgument() = step2 and
      step2.getAParameter().getName() = "$scope" and
      step2.getAParameter() = scopeSource and 
      scopeSource.getAPropertyReference() = this
    )
  }
}
