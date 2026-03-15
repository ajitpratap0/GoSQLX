import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import type { APIContext } from 'astro';

export async function GET(context: APIContext) {
  const posts = await getCollection('blog');
  const sortedPosts = posts.sort((a, b) => {
    const dateA = a.data?.date ? new Date(a.data.date) : new Date(0);
    const dateB = b.data?.date ? new Date(b.data.date) : new Date(0);
    return dateB.getTime() - dateA.getTime();
  });

  return rss({
    title: 'GoSQLX Release Notes',
    description: 'Latest releases and updates for GoSQLX',
    site: context.site!,
    items: sortedPosts.map((post) => ({
      title: post.data?.title || post.id,
      pubDate: post.data?.date ? new Date(post.data.date) : new Date(),
      link: `/blog/${post.id}/`,
    })),
  });
}
