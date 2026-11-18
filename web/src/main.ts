import { createApp, nextTick } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Composer from './views/Composer.vue'
import Uploaded from './views/Uploaded.vue'
import Share from './views/Share.vue'
import Mine from './views/Mine.vue'
import Terms from './views/Terms.vue'
import Privacy from './views/Privacy.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    // one morphing element behind two addresses, the back button keeps
    // working and /upload deep links straight into the open panel
    { path: '/', component: Composer },
    { path: '/upload', component: Composer },
    { path: '/uploaded', component: Uploaded },
    { path: '/s/:token', component: Share },
    { path: '/mine', component: Mine },
    { path: '/terms', component: Terms },
    { path: '/privacy', component: Privacy },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

// every page card carries the same view transition name, so navigating
// between pages morphs circle into card into list the same way the
// composer morphs. the composer pair is skipped because that morph is css
// driven inside one component and a snapshot transition would fight it
const composerPaths = new Set(['/', '/upload'])
router.beforeEach((to) => {
  const canTransition =
    typeof document !== 'undefined' &&
    typeof document.startViewTransition === 'function' &&
    !window.matchMedia('(prefers-reduced-motion: reduce)').matches
  if (!canTransition) return true
  if (composerPaths.has(to.path) && composerPaths.has(router.currentRoute.value.path)) {
    return true
  }
  return new Promise<boolean>((resolve) => {
    document.startViewTransition(async () => {
      resolve(true)
      // let vue patch the dom and the browser paint before the snapshot
      await nextTick()
      await new Promise<void>((done) => requestAnimationFrame(() => done()))
    })
  })
})

createApp(App).use(router).mount('#app')
