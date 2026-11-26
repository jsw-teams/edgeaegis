/**
 * Compact Aho-Corasick multi-pattern phrase matcher for SecLang @pm / @pmFromFile.
 * Builds its trie and failure links lazily on first match so unused rule data files
 * consume zero startup CPU and zero heap memory on Cloudflare Workers.
 */

export interface PhraseMatcher {
  test(lower: string): boolean;
  match(lower: string, original: string): string | undefined;
}

interface AcNode {
  next: Map<number, number>;
  fail: number;
  /** Lowest original phrase index ending at this state (or via dictionary suffix link). */
  best: number;
}

export function createPhraseMatcher(phrases: string[]): PhraseMatcher {
  if (!phrases.length) {
    return {
      test: () => false,
      match: () => undefined,
    };
  }
  const emptyIndex = phrases.indexOf("");
  if (emptyIndex === 0) {
    return {
      test: () => true,
      match: () => "",
    };
  }
  // Small phrase lists (<= 8 entries) are faster with direct indexOf than automaton traversal.
  if (phrases.length <= 8) {
    return {
      test(lower: string) {
        for (let i = 0; i < phrases.length; i++) {
          if (lower.includes(phrases[i]!)) return true;
        }
        return false;
      },
      match(lower: string, original: string) {
        for (let i = 0; i < phrases.length; i++) {
          const phrase = phrases[i]!;
          const at = lower.indexOf(phrase);
          if (at >= 0) return original.slice(at, at + phrase.length);
        }
        return undefined;
      },
    };
  }

  let nodes: AcNode[] | undefined;

  function build(): AcNode[] {
    const trie: AcNode[] = [{ next: new Map(), fail: 0, best: -1 }];
    for (let index = 0; index < phrases.length; index++) {
      const phrase = phrases[index]!;
      let state = 0;
      for (let i = 0; i < phrase.length; i++) {
        const ch = phrase.charCodeAt(i);
        let next = trie[state]!.next.get(ch);
        if (next === undefined) {
          next = trie.length;
          trie[state]!.next.set(ch, next);
          trie.push({ next: new Map(), fail: 0, best: -1 });
        }
        state = next;
      }
      if (trie[state]!.best < 0) trie[state]!.best = index;
    }
    const queue: number[] = [];
    for (const child of trie[0]!.next.values()) queue.push(child);
    for (let head = 0; head < queue.length; head++) {
      const state = queue[head]!;
      const node = trie[state]!;
      for (const [ch, child] of node.next) {
        queue.push(child);
        let fail = node.fail;
        while (fail !== 0 && !trie[fail]!.next.has(ch)) fail = trie[fail]!.fail;
        const target = trie[fail]!.next.get(ch) ?? 0;
        const childNode = trie[child]!;
        childNode.fail = target;
        const failBest = trie[target]!.best;
        if (failBest >= 0 && (childNode.best < 0 || failBest < childNode.best)) {
          childNode.best = failBest;
        }
      }
    }
    return trie;
  }

  return {
    test(lower: string) {
      if (emptyIndex >= 0) return true;
      if (!nodes) nodes = build();
      const trie = nodes;
      let state = 0;
      for (let i = 0; i < lower.length; i++) {
        const ch = lower.charCodeAt(i);
        while (state !== 0 && !trie[state]!.next.has(ch)) state = trie[state]!.fail;
        state = trie[state]!.next.get(ch) ?? 0;
        if (trie[state]!.best >= 0) return true;
      }
      return false;
    },
    match(lower: string, original: string) {
      if (!nodes) nodes = build();
      const trie = nodes;
      let state = 0;
      let bestIndex = emptyIndex;
      for (let i = 0; i < lower.length; i++) {
        const ch = lower.charCodeAt(i);
        while (state !== 0 && !trie[state]!.next.has(ch)) state = trie[state]!.fail;
        state = trie[state]!.next.get(ch) ?? 0;
        const found = trie[state]!.best;
        if (found >= 0 && (bestIndex < 0 || found < bestIndex)) {
          bestIndex = found;
          if (bestIndex === 0) break;
        }
      }
      if (bestIndex < 0) return undefined;
      const phrase = phrases[bestIndex]!;
      const at = lower.indexOf(phrase);
      return at < 0 ? undefined : original.slice(at, at + phrase.length);
    },
  };
}
