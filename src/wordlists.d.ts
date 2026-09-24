// Type declarations for wordlist text imports (bundled via wrangler Text rules).
declare module "*.txt" {
  const content: string;
  export default content;
}
