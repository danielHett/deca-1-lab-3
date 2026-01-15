package analysis.exercise;

import analysis.TaintAnalysisFlowFunctions;
import analysis.VulnerabilityReporter;
import analysis.fact.DataFlowFact;
import com.google.common.collect.Sets;
import heros.FlowFunction;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootMethod;

import java.util.Collections;
import java.util.Set;

public class Exercise1FlowFunctions extends TaintAnalysisFlowFunctions {

    private final VulnerabilityReporter reporter;

    public Exercise1FlowFunctions(VulnerabilityReporter reporter) {
        this.reporter = reporter;
    }

    @Override
    public FlowFunction<DataFlowFact> getCallFlowFunction(Stmt callSite, SootMethod callee) {
        return fact -> {
            if (fact.equals(DataFlowFact.getZeroInstance()))
                return Collections.emptySet();
            prettyPrint(callSite, fact);
            Set<DataFlowFact> out = Sets.newHashSet();

            // TODO: Implement Exercise 1c) here

            return out;
        };
    }

    public FlowFunction<DataFlowFact> getCallToReturnFlowFunction(final Stmt call, Stmt returnSite) {
        /**
         * The purpose of this method is to generate a flow function based on the
         * statement passed. Note that unlike the flow functions from the monotone
         * framework, we call this flow function once per element
         * in the input set, which is why *val* is just one dataflow fact, and not an
         * entire set.
         */
        return val -> {
            // Our set of dataflow facts.
            Set<DataFlowFact> out = Sets.newHashSet();

            // If *val* was in the set before, it should be brought back from the caller
            // context.
            out.add(val);

            // Here we want to cover the case of calling *getParameter*. In this case, the
            // caller context should add the variable on the left.
            if (call.toString().contains("getParameter")) {
                // First check that there is an LValue.
                if (call.getDef().isPresent()) {
                    Local leftVar = (Local) call.getDef().get();
                    out.add(new DataFlowFact(leftVar));
                }
            }

            // *toString* is like direct assignment.
            modelStringOperations(val, out, call);

            prettyPrint(call, val);

            // Here we catch any errors.
            if (call.toString().contains("executeQuery")) {
                Value arg = call.getInvokeExpr().getArg(0);
                if (val.getVariable().equals(arg)) {
                    reporter.reportVulnerability();
                }
            }

            return out;
        };
    }

    private void modelStringOperations(DataFlowFact fact, Set<DataFlowFact> out,
            Stmt callSiteStmt) {
        Exercise3FlowFunctions.handleCallSite(fact, out, callSiteStmt);

        /*
         * For any call x = var.toString(), if the base variable var is tainted, then x
         * is tainted.
         */
        if (callSiteStmt instanceof JAssignStmt && callSiteStmt.toString().contains("toString()")) {
            if (callSiteStmt.getInvokeExpr() instanceof AbstractInstanceInvokeExpr) {
                AbstractInstanceInvokeExpr AbstractInstanceInvokeExpr = (AbstractInstanceInvokeExpr) callSiteStmt
                        .getInvokeExpr();
                if (fact.getVariable().equals(AbstractInstanceInvokeExpr.getBase())) {
                    Value leftOp = ((JAssignStmt) callSiteStmt).getLeftOp();
                    if (leftOp instanceof Local) {
                        out.add(new DataFlowFact((Local) leftOp));
                    }
                }
            }
        }
    }

    @Override
    public FlowFunction<DataFlowFact> getNormalFlowFunction(final Stmt curr, Stmt succ) {
        return fact -> {
            System.out.println("Inside of getNormalFlowFunction");
            // prettyPrint(curr, fact);
            // prettyPrint(succ, fact);
            Set<DataFlowFact> out = Sets.newHashSet();
            out.add(fact);

            // TODO: Implement Exercise 1b) here

            return out;
        };
    }

    @Override
    public FlowFunction<DataFlowFact> getReturnFlowFunction(Stmt callSite, SootMethod callee, Stmt exitStmt,
            Stmt retSite) {
        return fact -> {
            prettyPrint(callSite, fact);
            return Collections.emptySet();
        };
    }
}
