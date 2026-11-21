import { createApp, nextTick } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Composer from './views/Composer.vue'
import Sending from './views/Sending.vue'
import Uploaded from './views/Uploaded.vue'
import Share from './views/Share.vue'
import Admin from './views/Admin.vue'
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
    { path: '/sending', component: Sending },
    { path: '/uploaded', component: Uploaded },
    { path: '/s/:token', component: Share },
    { path: '/mine', component: Mine },
    { path: '/admin', component: Admin },
    { path: '/terms', component: Terms },
    { path: '/privacy', component: Privacy },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

// every page card carries the same view transition name, so navigating
// between pages morphs circle into card into list the same way the
// composer morphs. the composer pair is skipped because that morph is css
// driven inside one component and a snapshot transition would fight it.
// the callback resolves the guard and waits only for vue's dom patch,
// anything heavier freezes the old snapshot and stalls the router
const composerPaths = new Set(['/', '/upload'])
router.beforeEach((to) => {
  const canTransition =
    typeof document !== 'undefined' &&
    typeof document.startViewTransition === 'function' &&
    document.visibilityState === 'visible' &&
    !window.matchMedia('(prefers-reduced-motion: reduce)').matches
  if (!canTransition) return true
  if (composerPaths.has(to.path) && composerPaths.has(router.currentRoute.value.path)) {
    return true
  }
  return new Promise<boolean>((resolve) => {
    let settled = false
    const go = () => {
      if (!settled) {
        settled = true
        resolve(true)
      }
    }
    // a deferred or refused transition must never hold the route hostage
    const guard = setTimeout(go, 250)
    try {
      document.startViewTransition(async () => {
        go()
        clearTimeout(guard)
        await nextTick()
      })
    } catch {
      clearTimeout(guard)
      go()
    }
  })
})

createApp(App).use(router).mount('#app')
