"""Bounded parsed structures and exact source spans used by scanner and fixes."""
from io import StringIO
import time

import hcl2
import yaml

MAX_DEPTH = 64
MAX_NODES = 20000
MAX_DOCUMENTS = 64


def validate_graph(value):
    visited, active = set(), set()
    count = 0
    deadline = time.monotonic() + 2
    def walk(obj, depth):
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH or time.monotonic() > deadline:
            raise ValueError("Configuration structure exceeds scan limits")
        if not isinstance(obj, (dict, list)):
            return
        identity = id(obj)
        if identity in active:
            raise ValueError("Recursive configuration references are unsupported")
        if identity in visited:
            return
        active.add(identity)
        for item in (obj.values() if isinstance(obj, dict) else obj):
            walk(item, depth + 1)
        active.remove(identity)
        visited.add(identity)
    walk(value, 0)


class BoundedSafeLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent, index):
        self._depth += 1
        self._nodes += 1
        try:
            if self._depth > MAX_DEPTH or self._nodes > MAX_NODES:
                raise ValueError("YAML nesting or node quota exceeded")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node, deep=False):
        keys = set()
        for key, _ in node.value:
            value = self.construct_object(key, deep=deep)
            try:
                if value in keys:
                    raise ValueError("Duplicate YAML keys are unsupported")
                keys.add(value)
            except TypeError:
                raise ValueError("YAML mapping keys must be scalar") from None
        return super().construct_mapping(node, deep=deep)


def yaml_documents(content):
    documents = []
    loader = BoundedSafeLoader(content)
    try:
        while loader.check_data():
            if len(documents) >= MAX_DOCUMENTS:
                raise ValueError("YAML document quota exceeded")
            doc = loader.get_data()
            validate_graph(doc)
            documents.append(doc)
    finally:
        loader.dispose()
    return documents


def yaml_node(content, pointer):
    parts = pointer.split("/")
    document = int(parts[1])
    nodes = list(yaml.compose_all(content, Loader=BoundedSafeLoader))
    node = nodes[document]
    for part in parts[2:]:
        if isinstance(node, yaml.SequenceNode):
            node = node.value[int(part)]
        elif isinstance(node, yaml.MappingNode):
            matches = [v for k, v in node.value if k.value == part]
            if len(matches) != 1:
                raise ValueError("Ambiguous YAML source location")
            node = matches[0]
        else:
            raise ValueError("Invalid YAML source location")
    return node


def yaml_scalar(content, pointer):
    """Resolve a known schema pointer to one scalar's exact original source span."""
    node = yaml_node(content, pointer)
    if not isinstance(node, yaml.ScalarNode):
        raise ValueError("Expected a scalar source location")
    return node.start_mark.index, node.end_mark.index, node.start_mark.line + 1


def terraform_blocks(content):
    parsed = hcl2.parse(StringIO(content))
    tree = parsed.to_lark() if hasattr(parsed, "to_lark") else parsed
    body = tree.children[0]
    return [node for node in body.children
            if getattr(node, "data", "") == "block"
            and str(node.children[0].children[0]) == "resource"]


def terraform_attribute(content, resource, attribute, *, blocks=None):
    index = int(resource.split("/")[1])
    block = (blocks if blocks is not None else terraform_blocks(content))[index]
    bodies = [c for c in block.children if getattr(c, "data", "") == "body"]
    matches = [c for c in bodies[0].children
               if getattr(c, "data", "") == "attribute" and str(c.children[0].children[0]) == attribute]
    if len(matches) != 1:
        raise ValueError("Ambiguous Terraform attribute")
    value = matches[0].children[-1]
    return value.meta.start_pos, value.meta.end_pos, value.meta.line
