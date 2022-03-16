import yaramod as ym


class YaraAstObserver(ym.ObservingVisitor):
    def __init__(self, file_mapper):
        super(YaraAstObserver, self).__init__()
        self.strings_offsets_map = []
        self.file_mapper = file_mapper

    def visit_StringExpression(self, expr):
        self._add_to_offset_map(expr.id, "String", "*", "*")

    def visit_StringWildcardExpression(self, expr):
        pass

    def visit_StringAtExpression(self, expr):

        self._add_to_offset_map(expr.id, "at", expr.at_expr.get_text(), expr.at_expr.get_text())

        expr.at_expr.accept(self)

    def visit_StringInRangeExpression(self, expr):
        low = expr.range_expr.low
        high = expr.range_expr.high

        if isinstance(low, ym.StringOffsetExpression):
            low = low.index_expr.value
        if isinstance(high, ym.StringOffsetExpression):
            high = high.index_expr.value
        if isinstance(low, ym.IntLiteralExpression):
            low = low.value
        if isinstance(high, ym.IntLiteralExpression):
            high = high.value

        self._add_to_offset_map(expr.id, "in_range", low, high)
        expr.range_expr.accept(self)

    def visit_StringCountExpression(self, expr):
        pass

    def visit_StringOffsetExpression(self, expr):
        if expr.index_expr:
            expr.index_expr.accept(self)

    def visit_StringLengthExpression(self, expr):
        if expr.index_expr:
            expr.index_expr.accept(self)

    def visit_NotExpression(self, expr):
        expr.operand.accept(self)

    def visit_UnaryMinusExpression(self, expr):
        expr.operand.accept(self)

    def visit_BitwiseNotExpression(self, expr):
        expr.operand.accept(self)

    def visit_AndExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_OrExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_LtExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_GtExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_LeExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_GeExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def helper_trigger_intfunc(self, func_name, func_arg, value):
        signed = False if func_name.startswith("uint") else True
        byteorder = "big" if func_name.endswith("be") else "little"
        size_in_bytes = int(func_name.rstrip("be").lstrip("u").lstrip("int")) // 8

        if isinstance(func_arg, ym.IntLiteralExpression):
            curr_resolve = value.to_bytes(size_in_bytes, byteorder=byteorder, signed=signed)
            return [(curr_resolve, "IntFunction", func_arg.value, func_arg.value + size_in_bytes)]

        if isinstance(func_arg, ym.IntFunctionExpression):
            first_free_idx = self.file_mapper.reserve_first_free_spot(size_in_bytes)
            next_functions_results = self.helper_trigger_intfunc(func_arg.function, func_arg.argument, value)
            curr_resolve = first_free_idx.to_bytes(size_in_bytes, byteorder=byteorder, signed=signed)
            return next_functions_results\
                + [(curr_resolve, "IntFunction", first_free_idx, first_free_idx + size_in_bytes)]

    def helper_rotate_ptrs(self, offsets):
        offset_vars = [offset[0] for offset in offsets]
        offset_vars = offset_vars[1:] + offset_vars[:1]
        offsets_to_ret = []
        for index, offset in enumerate(offsets):
            offsets_to_ret.append((offset_vars[index],) + offset[1:4])

        return offsets_to_ret

    def helper_add_int_functions(self, function, argument, value):
        offsets = self.helper_trigger_intfunc(function, argument, value)
        offsets = self.helper_rotate_ptrs(offsets)
        for curr_offset in offsets:
            self._add_to_offset_map(*curr_offset)

    def visit_EqExpression(self, expr):

        if isinstance(expr.left_operand, ym.IntFunctionExpression) and isinstance(expr.right_operand, ym.IntLiteralExpression):
            self.helper_add_int_functions(expr.left_operand.function, expr.left_operand.argument, expr.right_operand.value)
        elif isinstance(expr.right_operand, ym.IntFunctionExpression) and isinstance(expr.left_operand, ym.IntLiteralExpression):
            self.helper_add_int_functions(expr.right_operand.function, expr.right_operand.argument, expr.left_operand.value)

        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_NeqExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_ContainsExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_MatchesExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_PlusExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_MinusExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_MultiplyExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_DivideExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_ModuloExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_BitwiseXorExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_BitwiseAndExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_BitwiseOrExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_ShiftLeftExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_ShiftRightExpression(self, expr):
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_ForDictExpression(self, expr):
        expr.variable.accept(self)
        expr.iterable.accept(self)
        expr.body.accept(self)

    def visit_ForArrayExpression(self, expr):
        expr.variable.accept(self)
        expr.iterable.accept(self)
        expr.body.accept(self)

    def visit_ForStringExpression(self, expr):
        expr.variable.accept(self)
        expr.iterable.accept(self)
        expr.body.accept(self)

    def visit_OfExpression(self, expr):
        self._add_to_offset_map(None, 'of', expr.variable, expr.iterable)

        expr.variable.accept(self)
        expr.iterable.accept(self)

    def visit_IteratorExpression(self, expr):
        for elem in expr.elements:
            elem.accept(self)

    def visit_SetExpression(self, expr):
        for elem in expr.elements:
            elem.accept(self)

    def visit_RangeExpression(self, expr):
        expr.low.accept(self)
        expr.high.accept(self)

    def visit_IdExpression(self, expr):
        pass

    def visit_StructAccessExpression(self, expr):
        expr.structure.accept(self)

    def visit_ArrayAccessExpression(self, expr):
        expr.array.accept(self)
        expr.accessor.accept(self)

    def visit_FunctionCallExpression(self, expr):
        expr.function.accept(self)

        for arg in expr.arguments:
            arg.accept(self)

    def visit_BoolLiteralExpression(self, expr):
        pass

    def visit_StringLiteralExpression(self, expr):
        pass

    def visit_IntLiteralExpression(self, expr):
        pass

    def visit_DoubleLiteralExpression(self, expr):
        pass

    def visit_FilesizeExpression(self, expr):
        pass

    def visit_EntrypointExpression(self, expr):
        pass

    def visit_AllExpression(self, expr):
        pass

    def visit_AnyExpression(self, expr):
        pass

    def visit_NoneExpression(self, expr):
        pass

    def visit_ThemExpression(self, expr):
        pass

    def visit_ParenthesesExpression(self, expr):
        expr.enclosed_expr.accept(self)

    def visit_IntFunctionExpression(self, expr):
        expr.argument.accept(self)

    def visit_RegexpExpression(self, expr):
        pass

    def _add_to_offset_map(self, var, operation, min_offset, max_offset):
        self.strings_offsets_map.append({"var": var,
                                         "operation": operation,
                                         "min_offset": min_offset,
                                         "max_offset": max_offset})