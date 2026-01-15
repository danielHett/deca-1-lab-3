package analysis.exercise;

import analysis.TaintAnalysisFlowFunctions;
import analysis.VulnerabilityReporter;
import analysis.fact.DataFlowFact;
import com.google.common.collect.Sets;
import heros.FlowFunction;
import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.LValue;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.ref.JInstanceFieldRef;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootMethod;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class Exercise2FlowFunctions extends TaintAnalysisFlowFunctions {

    private final VulnerabilityReporter reporter;

    public Exercise2FlowFunctions(VulnerabilityReporter reporter) {
        this.reporter = reporter;
    }

    @Override
    public FlowFunction<DataFlowFact> getCallFlowFunction(Stmt callSite, SootMethod callee) {
        return fact -> {
            prettyPrint(callSite, fact);

            // Always carry over facts.
            Set<DataFlowFact> out = Sets.newHashSet();
            out.add(fact);

            if (callSite.containsInvokeExpr()) {
                AbstractInvokeExpr invokeExpr = callSite.getInvokeExpr();

                // Find all arguments in the invoke expression that are equal to the fact.
                List<Integer> taintedArgumentIndicies = new ArrayList<Integer>();
                for (int i = 0; i < invokeExpr.getArgCount(); i++) {
                    Immediate localOrConstant = invokeExpr.getArg(i);

                    // We only care about locals.
                    if (!(localOrConstant instanceof Local))
                        continue;

                    // If it's tainted, we mark the index.
                    Local local = (Local) localOrConstant;
                    if (fact.getVariable().equals(local))
                        taintedArgumentIndicies.add(i);
                }

                for (int i : taintedArgumentIndicies) {
                    out.add(new DataFlowFact(callee.getBody().getParameterLocal(i)));
                }
            }

            System.out.println(out);
            return out;
        };
    }

    public FlowFunction<DataFlowFact> getCallToReturnFlowFunction(final Stmt callSiteStmt, Stmt returnSite) {
        return fact -> {
            prettyPrint(callSiteStmt, fact);

            // Our set of dataflow facts.
            // Always carry over facts.
            Set<DataFlowFact> out = Sets.newHashSet();
            out.add(fact);

            // Here we want to cover the case of calling *getParameter*. In this case, the
            // caller context should add the variable on the left.
            if (callSiteStmt.toString().contains("getParameter")) {
                // First check that there is an LValue.
                if (callSiteStmt.getDef().isPresent()) {
                    Local leftVar = (Local) callSiteStmt.getDef().get();
                    System.out.println("VARIABLE " + leftVar.toString());
                    out.add(new DataFlowFact(leftVar));
                }
            }

            // *toString* is like direct assignment.
            modelStringOperations(fact, out, callSiteStmt);

            // Here we catch any errors.
            if (callSiteStmt.toString().contains("executeQuery")) {
                Value arg = callSiteStmt.getInvokeExpr().getArg(0);
                if (fact.getVariable().equals(arg)) {
                    reporter.reportVulnerability();
                }
            }

            System.out.println(out);
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
                AbstractInstanceInvokeExpr instanceInvokeExpr = (AbstractInstanceInvokeExpr) callSiteStmt
                        .getInvokeExpr();

                if (fact.getVariable().equals(instanceInvokeExpr.getBase())) {
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
            prettyPrint(curr, fact);

            Set<DataFlowFact> out = Sets.newHashSet();
            out.add(fact);

            // Is this an assignment statement?
            if (curr instanceof JAssignStmt) {
                JAssignStmt assignStmt = (JAssignStmt) curr;

                if ((assignStmt.getLeftOp() instanceof Local || assignStmt.getLeftOp() instanceof JInstanceFieldRef)
                        && (assignStmt.getRightOp() instanceof Local
                                || assignStmt.getRightOp() instanceof JInstanceFieldRef)) {

                    DataFlowFact left;
                    if (assignStmt.getLeftOp() instanceof Local)
                        left = new DataFlowFact((Local) (assignStmt.getLeftOp()));
                    else
                        left = new DataFlowFact(((JInstanceFieldRef) (assignStmt.getLeftOp())).getFieldSignature());

                    DataFlowFact right;
                    if (assignStmt.getRightOp() instanceof Local)
                        right = new DataFlowFact((Local) (assignStmt.getRightOp()));
                    else
                        right = new DataFlowFact(((JInstanceFieldRef) (assignStmt.getRightOp())).getFieldSignature());

                    // Assignment should destroy any taint.
                    out.remove(left);
                    // But if the right value is tainted, then we can add the left back to the set.
                    if (fact.equals(right)) {
                        out.add(left);
                    }
                }
            }

            System.out.println(out);
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
