<script lang="ts">
	import { toast } from 'svelte-sonner';
	import dayjs from 'dayjs';
	import { createEventDispatcher } from 'svelte';
	import { onMount, getContext } from 'svelte';

	import { updateUserById } from '$lib/apis/users';
	import Switch from '$lib/components/common/Switch.svelte';
	import Modal from '$lib/components/common/Modal.svelte';
	import localizedFormat from 'dayjs/plugin/localizedFormat';

	const i18n = getContext('i18n');
	const dispatch = createEventDispatcher();
	dayjs.extend(localizedFormat);

	export let show = false;
	export let selectedUser;
	export let sessionUser;

	let _user = {
		id: '',
		name: '',
		description: '',
		price: null,
		credits: null,
		duration: null,
		is_active: true
	};

	const submitHandler = async () => {
		const res = await updateUserById(localStorage.token, selectedUser.id, _user).catch((error) => {
			toast.error(`${error}`);
		});

		if (res) {
			dispatch('save');
			show = false;
		}
	};

	onMount(() => {
		if (selectedUser) {
			_user = selectedUser;
		}
	});
</script>

<Modal size="sm" bind:show>
	<div>
		<div class=" flex justify-between dark:text-gray-300 px-5 pt-4 pb-2">
			<div class=" text-lg font-medium self-center">{$i18n.t('editmenu')}</div>
			<button
				class="self-center"
				on:click={() => {
					show = false;
				}}
			>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					viewBox="0 0 20 20"
					fill="currentColor"
					class="w-5 h-5"
				>
					<path
						d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"
					/>
				</svg>
			</button>
		</div>

		<div class="flex flex-col md:flex-row w-full md:space-x-4 dark:text-gray-200">
			<div class=" flex flex-col w-full sm:flex-row sm:justify-center sm:space-x-6">
				<form
					class="flex flex-col w-full"
					on:submit|preventDefault={() => {
						submitHandler();
					}}
				>
					<!-- <div class=" flex items-center rounded-md px-5 py-2 w-full">
						<div>
							<div class=" self-center capitalize font-semibold">{selectedUser.name}</div>

							<div class="text-xs text-gray-500">
								{$i18n.t('Created at')}
								{dayjs(selectedUser.created_at * 1000).format('LL')}
							</div>
						</div>
					</div> -->

					<div class=" px-5 pt-3 pb-5">
						<div class=" flex flex-col space-y-1.5">
							<div class="flex flex-col w-full">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menuname')}</div>

								<div class="flex-1">
									<input
										class="w-full rounded-sm text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
										type="text"
										bind:value={_user.name}
										placeholder={$i18n.t('menuname_placeholder')}
										autocomplete="off"
										required
									/>
								</div>
							</div>

							<div class="flex flex-col w-full">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menudescription')}</div>

								<div class="flex-1">
									<textarea
										class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
										bind:value={_user.description}
										placeholder={$i18n.t('menudescription_placeholder')}
										required
									/>
								</div>
							</div>

							<div class="flex flex-col w-full">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menuduration')}</div>
								<div class="flex-1">
									<input
										class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
										type="number"
										bind:value={_user.duration}
										placeholder={$i18n.t('menuduration_placeholder')}
										autocomplete="off"
										required
									/>
								</div>
							</div>

							<div class="flex flex-col w-full">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menuprice')}</div>

								<div class="flex-1">
									<input
										class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
										type="number"
										bind:value={_user.price}
										placeholder={$i18n.t('menuprice_placeholder')}
										autocomplete="off"
									/>
								</div>
							</div>
							<div class="flex flex-col w-full">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menucredits')}</div>

								<div class="flex-1">
									<input
										class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
										type="number"
										bind:value={_user.credits}
										placeholder={$i18n.t('menucredits_placeholder')}
										autocomplete="off"
									/>
								</div>
							</div>
							<div class="flex justify-between w-full my-1">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menuis_active')}</div>

								<Switch bind:state={_user.is_active} />
							</div>
						</div>

						<div class="flex justify-end pt-3 text-sm font-medium">
							<button
								class="px-3.5 py-1.5 text-sm font-medium bg-black hover:bg-gray-900 text-white dark:bg-white dark:text-black dark:hover:bg-gray-100 transition rounded-full flex flex-row space-x-1 items-center"
								type="submit"
							>
								{$i18n.t('Save')}
							</button>
						</div>
					</div>
				</form>
			</div>
		</div>
	</div>
</Modal>

<style>
	input::-webkit-outer-spin-button,
	input::-webkit-inner-spin-button {
		/* display: none; <- Crashes Chrome on hover */
		-webkit-appearance: none;
		margin: 0; /* <-- Apparently some margin are still there even though it's hidden */
	}

	.tabs::-webkit-scrollbar {
		display: none; /* for Chrome, Safari and Opera */
	}

	.tabs {
		-ms-overflow-style: none; /* IE and Edge */
		scrollbar-width: none; /* Firefox */
	}

	input[type='number'] {
		-moz-appearance: textfield; /* Firefox */
	}
</style>
