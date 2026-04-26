"""Safe policy evaluation engine."""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PolicyRule:
    name: str
    description: str = ""
    priority: int = 100
    match_domain: Optional[str] = None
    match_operations: List[str] = field(default_factory=list)
    condition: str = ""
    action: str = "deny"
    audit_level: str = "standard"
    risk_level: str = "medium"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PolicyRule":
        match = d.get("match", {})
        ops = match.get("operation", [])
        if isinstance(ops, str):
            ops = [ops]
        return cls(
            name=d["name"],
            description=d.get("description", ""),
            priority=d.get("priority", 100),
            match_domain=match.get("domain"),
            match_operations=ops,
            condition=d.get("condition", ""),
            action=d.get("action", "deny"),
            audit_level=d.get("audit", "standard"),
            risk_level=d.get("risk_level", "medium"),
        )


class SafeEvaluator:
    """Recursive AST evaluator with no eval/exec calls."""

    ALLOWED_BUILTINS = {
        "len", "str", "int", "float", "bool",
        "any", "all", "sorted", "min", "max", "sum", "abs", "round",
        "enumerate", "zip", "map", "filter",
        "list", "tuple", "set", "dict", "range",
    }

    def __init__(self, context: Dict[str, Any]):
        self.context = context

    def evaluate(self, expr: str) -> Any:
        tree = ast.parse(expr, mode="eval")
        return self._eval_node(tree.body)

    def _eval_node(self, node: ast.AST) -> Any:
        if isinstance(node, ast.BoolOp):
            values = [self._eval_node(v) for v in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            if isinstance(node.op, ast.Or):
                return any(values)
            raise ValueError(f"Unsupported boolop: {type(node.op).__name__}")

        if isinstance(node, ast.BinOp):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            return self._binop(left, right, node.op)

        if isinstance(node, ast.UnaryOp):
            operand = self._eval_node(node.operand)
            if isinstance(node.op, ast.Not):
                return not operand
            if isinstance(node.op, ast.UAdd):
                return +operand
            if isinstance(node.op, ast.USub):
                return -operand
            raise ValueError(f"Unsupported unary: {type(node.op).__name__}")

        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval_node(comparator)
                if not self._compare(left, op, right):
                    return False
                left = right
            return True

        if isinstance(node, ast.Call):
            func = self._eval_node(node.func)
            args = [self._eval_node(arg) for arg in node.args]
            kwargs = {kw.arg: self._eval_node(kw.value) for kw in node.keywords}
            return func(*args, **kwargs)

        if isinstance(node, ast.Name):
            if node.id in self.context:
                return self.context[node.id]
            if node.id in self.ALLOWED_BUILTINS:
                return getattr(__builtins__, node.id)
            raise ValueError(f"Unknown or disallowed name: {node.id}")

        if isinstance(node, ast.Constant):
            return node.value
        if hasattr(ast, "Str") and isinstance(node, ast.Str):  # pragma: no cover (py<3.8)
            return node.s
        if hasattr(ast, "Num") and isinstance(node, ast.Num):  # pragma: no cover (py<3.8)
            return node.n

        if isinstance(node, ast.List):
            return [self._eval_node(e) for e in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self._eval_node(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            keys = [self._eval_node(k) for k in node.keys]
            values = [self._eval_node(v) for v in node.values]
            return dict(zip(keys, values))
        if isinstance(node, ast.Set):
            return {self._eval_node(e) for e in node.elts}

        if isinstance(node, ast.Subscript):
            value = self._eval_node(node.value)
            slice_node = node.slice
            # Python 3.8 compat: Index wrapper
            if hasattr(ast, "Index") and isinstance(slice_node, ast.Index):  # pragma: no cover
                slice_node = slice_node.value
            if isinstance(slice_node, ast.Slice):
                lower = self._eval_node(slice_node.lower) if slice_node.lower else None
                upper = self._eval_node(slice_node.upper) if slice_node.upper else None
                step = self._eval_node(slice_node.step) if slice_node.step else None
                return value[slice(lower, upper, step)]
            index = self._eval_node(slice_node)
            return value[index]

        if isinstance(node, ast.Attribute):
            value = self._eval_node(node.value)
            return getattr(value, node.attr)

        if isinstance(node, ast.IfExp):
            test = self._eval_node(node.test)
            return self._eval_node(node.body) if test else self._eval_node(node.orelse)

        if isinstance(node, ast.ListComp):
            return self._eval_comprehension(node.elt, node.generators, list)
        if isinstance(node, ast.SetComp):
            return self._eval_comprehension(node.elt, node.generators, set)
        if isinstance(node, ast.GeneratorExp):
            return self._eval_comprehension(node.elt, node.generators, list)
        if isinstance(node, ast.DictComp):
            return self._eval_dict_comprehension(node)

        raise ValueError(f"Unsupported AST node: {type(node).__name__}")

    def _binop(self, left: Any, right: Any, op: ast.operator) -> Any:
        if isinstance(op, ast.Add):
            return left + right
        if isinstance(op, ast.Sub):
            return left - right
        if isinstance(op, ast.Mult):
            return left * right
        if isinstance(op, ast.Div):
            return left / right
        if isinstance(op, ast.FloorDiv):
            return left // right
        if isinstance(op, ast.Mod):
            return left % right
        if isinstance(op, ast.Pow):
            return left ** right
        if isinstance(op, ast.LShift):
            return left << right
        if isinstance(op, ast.RShift):
            return left >> right
        if isinstance(op, ast.BitOr):
            return left | right
        if isinstance(op, ast.BitXor):
            return left ^ right
        if isinstance(op, ast.BitAnd):
            return left & right
        if isinstance(op, ast.MatMult):
            return left @ right
        raise ValueError(f"Unsupported binary operator: {type(op).__name__}")

    def _compare(self, left: Any, op: ast.cmpop, right: Any) -> bool:
        if isinstance(op, ast.Eq):
            return left == right
        if isinstance(op, ast.NotEq):
            return left != right
        if isinstance(op, ast.Lt):
            return left < right
        if isinstance(op, ast.LtE):
            return left <= right
        if isinstance(op, ast.Gt):
            return left > right
        if isinstance(op, ast.GtE):
            return left >= right
        if isinstance(op, ast.Is):
            return left is right
        if isinstance(op, ast.IsNot):
            return left is not right
        if isinstance(op, ast.In):
            return left in right
        if isinstance(op, ast.NotIn):
            return left not in right
        raise ValueError(f"Unsupported comparison: {type(op).__name__}")

    def _eval_comprehension(self, elt_node: ast.AST, generators: List[ast.comprehension], collector: type):
        results = collector()
        self._comprehension_recursive(elt_node, generators, 0, {}, results.append if collector is list else results.add)
        return results

    def _comprehension_recursive(self, elt_node: ast.AST, generators: List[ast.comprehension], idx: int, local_vars: Dict[str, Any], adder):
        if idx >= len(generators):
            adder(self._eval_node(elt_node))
            return
        gen = generators[idx]
        iterable = self._eval_node(gen.iter)
        for item in iterable:
            self._assign_target(gen.target, item, local_vars)
            if gen.ifs:
                if not all(self._eval_node(if_node) for if_node in gen.ifs):
                    continue
            self._comprehension_recursive(elt_node, generators, idx + 1, local_vars, adder)

    def _eval_dict_comprehension(self, node: ast.DictComp):
        result = {}
        self._dict_comp_recursive(node.key, node.value, node.generators, 0, {}, result)
        return result

    def _dict_comp_recursive(self, key_node: ast.AST, val_node: ast.AST, generators: List[ast.comprehension], idx: int, local_vars: Dict[str, Any], result: dict):
        if idx >= len(generators):
            result[self._eval_node(key_node)] = self._eval_node(val_node)
            return
        gen = generators[idx]
        iterable = self._eval_node(gen.iter)
        for item in iterable:
            self._assign_target(gen.target, item, local_vars)
            if gen.ifs:
                if not all(self._eval_node(if_node) for if_node in gen.ifs):
                    continue
            self._dict_comp_recursive(key_node, val_node, generators, idx + 1, local_vars, result)

    def _assign_target(self, target: ast.AST, value: Any, local_vars: Dict[str, Any]):
        if isinstance(target, ast.Name):
            local_vars[target.id] = value
            self.context[target.id] = value
        elif isinstance(target, ast.Tuple):
            if not isinstance(value, (tuple, list)):
                raise ValueError("Cannot unpack non-iterable")
            for t, v in zip(target.elts, value):
                self._assign_target(t, v, local_vars)
        else:
            raise ValueError(f"Unsupported assignment target: {type(target).__name__}")


class PolicyEngine:
    def __init__(self, rules: List[PolicyRule]):
        self.rules = sorted(rules, key=lambda r: (-r.priority, r.name))

    @classmethod
    def from_file(cls, path: str) -> "PolicyEngine":
        with open(path) as f:
            data = json.load(f)
        rules = [PolicyRule.from_dict(r) for r in data.get("policies", [])]
        return cls(rules)

    def evaluate(self, domain: str, operation: str, target: Any,
                 identity: Any, params: Dict[str, Any]) -> Optional[PolicyRule]:
        for rule in self.rules:
            if rule.match_domain and rule.match_domain != domain:
                continue
            if rule.match_operations and operation not in rule.match_operations:
                continue
            if rule.condition:
                context = {
                    "target": target,
                    "identity": identity,
                    "params": params,
                    "domain": domain,
                    "operation": operation,
                    "env": {},
                }
                try:
                    evaluator = SafeEvaluator(context)
                    result = evaluator.evaluate(rule.condition)
                    if result:
                        return rule
                except Exception:
                    # Policy error: treat as non-match and continue
                    continue
            else:
                # No condition means unconditional match
                return rule
        return None


class PolicyError(Exception):
    pass
