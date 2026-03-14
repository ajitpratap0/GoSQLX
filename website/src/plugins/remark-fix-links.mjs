import { visit } from 'unist-util-visit';

export function remarkFixLinks() {
  return (tree) => {
    visit(tree, 'link', (node) => {
      if (node.url && node.url.endsWith('.md') && !node.url.startsWith('http')) {
        // Convert relative .md links to website routes
        // e.g., "USAGE_GUIDE.md" -> "/GoSQLX/docs/usage_guide/"
        // e.g., "../tutorials/01-foo.md" -> "/GoSQLX/docs/tutorials/01-foo/"
        let url = node.url;

        // Remove leading ../ or ./
        url = url.replace(/^\.\.\//, '').replace(/^\.\//, '');

        // Remove .md extension
        url = url.replace(/\.md$/, '');

        // Lowercase
        url = url.toLowerCase();

        // Prefix with base path
        node.url = `/GoSQLX/docs/${url}/`;
      }
    });
  };
}
