declare module "@solid/acl-check" {

  import { IndexedFormula, Node, ValueType, NamedNode } from "rdflib";

  export function getTrustedModesForOrigin(kb: IndexedFormula, doc: ValueType, isDirectory: boolean, aclDoc: ValueType, origin: ValueType, fetch: (node: NamedNode) => Promise<IndexedFormula>): Promise<Node[]>;

  export function accessDenied(kb: IndexedFormula, doc: ValueType, isDirectory: boolean, aclDoc: ValueType, agent: ValueType, modes: ValueType[], origin: ValueType, trustedOrigins: ValueType[] | undefined, originTrustedModes: Node[]): boolean;

}