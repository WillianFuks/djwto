<template>
  <q-page
    class="flex flex-center"
  >
    <q-card
      tag="div"
      bordered
      style="display:block; margin: auto; padding: auto, width:300px"
    >

    <q-img
      alt="djwto logo"
      src="~assets/logo.png"
      width="250px"
      height="150px"
      fit="fill"
      class="full-width"
    />

    <q-card-section>
      <q-form
        class="q-gutter-sm"
        @submit.prevent="onSubmit($event)"
      >

        <q-input
          v-model="username"
          square
          filled
          clearable
          type="text"
          label="username"
          name="username"
        >
          <template #prepend>
            <q-icon name="fa-solid fa-user" />
          </template>

        </q-input>

        <q-input
          v-model="pass"
          square
          filled
          clearable
          type="password"
          label="password"
          name="password"
        >
          <template #prepend>
            <q-icon name="fas fa-unlock-alt" />
          </template>

        </q-input>

      <q-btn
        unelevated
        color="warning"
        size="lg"
        class="q-px-md full-width"
        label="Login"
        type="submit"
      />

      </q-form>
    </q-card-section>

    </q-card>
  </q-page>
</template>

<script setup>
  import { ref } from 'vue'
  import { api } from 'boot/axios'
  import { useQuasar } from 'quasar'
  import { useRouter } from 'vue-router';

  const router = useRouter();
  const pass = ref('')
  const username = ref('')

  const $q = useQuasar()

  function onSubmit(event) {
    const formData = new FormData(event.target)

    if (!pass.value || !username.value) {
        $q.notify({
          color: 'red-5',
          textColor: 'white',
          icon: 'warning',
          message: 'Please make sure to fill both fields user and password!'
        })
        return
    }

    let res = api.post(
      'https://api.example.com:8002/login/',
      formData,
      {
        withCredentials: true,
        headers: { 'Content-Type': 'application/json' }
      }
    ).then((response) => {
      console.log(`response is: ${JSON.stringify(response)}`)
      router.push({path: '/main'})
    }).catch((r) => {
      const error = JSON.parse(r.response.data.error)
      for (let [key, value] of Object.entries(error)){
        if (key == '__all__') {
          key = ''
        }
        $q.notify({
          color: 'red-5',
          textColor: 'white',
          icon: 'warning',
          message: `${key} ${value}`
        })
      }
    })
  }
</script>
